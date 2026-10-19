// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/age"

	"github.com/iamvirul/sarc/crypto"
)

// The recipient block lists every wrapped copy of an archive's CEK (Version2+):
//
//	block    := count(2) | stanza*
//	stanza   := type(1) | body_len(4) | body
//	password := iterations(4) | salt(32) | nonce(12) | sealed_cek(48)
//	age      := a standard age file whose payload is the CEK
//
// Any one stanza a reader can open yields the CEK. Stanza count and types are public;
// salts, nonces, and age ephemeral shares reveal nothing about who the recipients are.
const (
	stanzaTypePassword byte = 0x01
	stanzaTypeAge      byte = 0x02

	// MaxRecipientBlockSize bounds the block before it is allocated.
	MaxRecipientBlockSize = 1 << 20
	// MaxPasswordRecipients bounds password stanzas, since each costs one PBKDF2 run
	// when a password is tried against the archive.
	MaxPasswordRecipients = 8

	passwordStanzaSize = 4 + crypto.SaltSize + crypto.NonceSize + crypto.KeySize + crypto.GCMTagSize
	stanzaHeaderSize   = 1 + 4
)

// ErrNoMatchingCredential is returned when no supplied password or identity opens any
// recipient stanza.
var ErrNoMatchingCredential = errors.New("archive: no matching password or identity")

// ErrMalformedRecipientBlock is returned when a recipient block cannot be parsed.
var ErrMalformedRecipientBlock = errors.New("archive: malformed recipient block")

// Credentials lists who can open an archive. Any one of them unlocks it in full.
type Credentials struct {
	Passwords     []string
	AgeRecipients []age.Recipient
}

// Unlockers lists the secrets a reader tries against an archive's recipient block.
type Unlockers struct {
	Password   string // empty means no password
	Identities []age.Identity
}

// SealRecipientBlock wraps cek for every credential in creds and returns the encoded block.
func SealRecipientBlock(cek [crypto.KeySize]byte, creds Credentials) ([]byte, error) {
	if len(creds.Passwords) == 0 && len(creds.AgeRecipients) == 0 {
		return nil, fmt.Errorf("archive/recipients: at least one password or age recipient is required")
	}
	if len(creds.Passwords) > MaxPasswordRecipients {
		return nil, fmt.Errorf("archive/recipients: %d password recipients, maximum %d", len(creds.Passwords), MaxPasswordRecipients)
	}

	count := len(creds.Passwords)
	if len(creds.AgeRecipients) > 0 {
		count++
	}
	block := binary.LittleEndian.AppendUint16(nil, uint16(count))
	for _, password := range creds.Passwords {
		if password == "" {
			return nil, fmt.Errorf("archive/recipients: empty password")
		}
		w, err := crypto.WrapCEKWithPassword(cek, password)
		if err != nil {
			return nil, fmt.Errorf("archive/recipients: wrap for password: %w", err)
		}
		block = appendStanza(block, stanzaTypePassword, encodePasswordWrap(w))
	}
	if len(creds.AgeRecipients) > 0 {
		blob, err := crypto.WrapCEKForAge(cek, creds.AgeRecipients)
		if err != nil {
			return nil, fmt.Errorf("archive/recipients: wrap for age recipients: %w", err)
		}
		block = appendStanza(block, stanzaTypeAge, blob)
	}
	if len(block) > MaxRecipientBlockSize {
		return nil, fmt.Errorf("archive/recipients: block is %d bytes, maximum %d", len(block), MaxRecipientBlockSize)
	}
	return block, nil
}

// OpenRecipientBlock returns the CEK from the first stanza that u can open. Password
// stanzas are tried only with a non-empty password and the age stanza only with
// identities. It returns ErrNoMatchingCredential when nothing matches.
func OpenRecipientBlock(block []byte, u Unlockers) ([crypto.KeySize]byte, error) {
	stanzas, err := parseRecipientBlock(block)
	if err != nil {
		return [crypto.KeySize]byte{}, err
	}
	for _, s := range stanzas {
		var cek [crypto.KeySize]byte
		switch {
		case s.kind == stanzaTypePassword && u.Password != "":
			cek, err = crypto.UnwrapCEKWithPassword(decodePasswordWrap(s.body), u.Password)
		case s.kind == stanzaTypeAge && len(u.Identities) > 0:
			cek, err = crypto.UnwrapCEKWithAge(s.body, u.Identities)
		default:
			continue
		}
		if err == nil {
			return cek, nil
		}
		if !errors.Is(err, crypto.ErrWrongCredential) {
			return [crypto.KeySize]byte{}, fmt.Errorf("%w: %w", ErrMalformedRecipientBlock, err)
		}
	}
	return [crypto.KeySize]byte{}, ErrNoMatchingCredential
}

type stanza struct {
	kind byte
	body []byte
}

func appendStanza(dst []byte, kind byte, body []byte) []byte {
	dst = append(dst, kind)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(body)))
	return append(dst, body...)
}

// parseRecipientBlock decodes and validates a block: known stanza types only, exact
// password stanza sizes, at most MaxPasswordRecipients password stanzas and one age
// stanza, no trailing bytes, and at least one stanza.
func parseRecipientBlock(block []byte) ([]stanza, error) {
	if len(block) < 2 {
		return nil, fmt.Errorf("%w: truncated count", ErrMalformedRecipientBlock)
	}
	count := int(binary.LittleEndian.Uint16(block))
	if count == 0 || count > MaxPasswordRecipients+1 {
		return nil, fmt.Errorf("%w: %d stanzas", ErrMalformedRecipientBlock, count)
	}
	stanzas := make([]stanza, 0, count)
	passwords, ages := 0, 0
	off := 2
	for i := 0; i < count; i++ {
		if len(block)-off < stanzaHeaderSize {
			return nil, fmt.Errorf("%w: truncated stanza header", ErrMalformedRecipientBlock)
		}
		kind := block[off]
		bodyLen := binary.LittleEndian.Uint32(block[off+1:])
		off += stanzaHeaderSize
		if uint64(bodyLen) > uint64(len(block)-off) {
			return nil, fmt.Errorf("%w: stanza runs past block", ErrMalformedRecipientBlock)
		}
		body := block[off : off+int(bodyLen)]
		off += int(bodyLen)
		switch kind {
		case stanzaTypePassword:
			passwords++
			if len(body) != passwordStanzaSize || passwords > MaxPasswordRecipients {
				return nil, fmt.Errorf("%w: bad password stanza", ErrMalformedRecipientBlock)
			}
		case stanzaTypeAge:
			ages++
			if ages > 1 || len(body) == 0 {
				return nil, fmt.Errorf("%w: bad age stanza", ErrMalformedRecipientBlock)
			}
		default:
			return nil, fmt.Errorf("%w: unknown stanza type 0x%02x", ErrMalformedRecipientBlock, kind)
		}
		stanzas = append(stanzas, stanza{kind: kind, body: body})
	}
	if off != len(block) {
		return nil, fmt.Errorf("%w: trailing bytes", ErrMalformedRecipientBlock)
	}
	return stanzas, nil
}

func encodePasswordWrap(w crypto.PasswordWrap) []byte {
	b := binary.LittleEndian.AppendUint32(make([]byte, 0, passwordStanzaSize), w.Iterations)
	b = append(b, w.Salt[:]...)
	b = append(b, w.Nonce[:]...)
	return append(b, w.Sealed[:]...)
}

// decodePasswordWrap expects a body already validated to passwordStanzaSize bytes.
func decodePasswordWrap(b []byte) crypto.PasswordWrap {
	var w crypto.PasswordWrap
	w.Iterations = binary.LittleEndian.Uint32(b)
	off := 4
	off += copy(w.Salt[:], b[off:])
	off += copy(w.Nonce[:], b[off:])
	copy(w.Sealed[:], b[off:])
	return w
}
