// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"

	"github.com/iamvirul/sarc/crypto"
)

// The recipient block lists every wrapped copy of an archive's CEK (Version2+):
//
//	block                 := count(2) | stanza*
//	stanza                := type(1) | body_len(4) | body
//	password              := iterations(4) | salt(32) | nonce(12) | sealed_cek(48)
//	age                   := a standard age file whose payload is the CEK
//	key_file              := salt(32) | nonce(12) | sealed_cek(48)
//	key_file_and_password := iterations(4) | salt(32) | nonce(12) | sealed_cek(48)
//
// Any one stanza a reader can open yields the CEK. Stanza count and types are public;
// salts, nonces, and age ephemeral shares reveal nothing about who the recipients are.
const (
	stanzaTypePassword        byte = 0x01
	stanzaTypeAge             byte = 0x02
	stanzaTypeKeyFile         byte = 0x03
	stanzaTypeKeyFilePassword byte = 0x04

	// MaxRecipientBlockSize bounds the block before it is allocated.
	MaxRecipientBlockSize = 1 << 20
	// MaxPasswordRecipients bounds password stanzas, since each costs one PBKDF2 run
	// when a password is tried against the archive.
	MaxPasswordRecipients = 8
	// MaxKeyFileRecipients bounds key file stanzas of each kind; a key file and password
	// stanza costs one PBKDF2 run when tried.
	MaxKeyFileRecipients = 8

	passwordStanzaSize = 4 + crypto.SaltSize + crypto.NonceSize + crypto.KeySize + crypto.GCMTagSize
	keyFileStanzaSize  = crypto.SaltSize + crypto.NonceSize + crypto.KeySize + crypto.GCMTagSize
	stanzaHeaderSize   = 1 + 4
	maxStanzas         = MaxPasswordRecipients + 2*MaxKeyFileRecipients + 1
)

// ErrNoMatchingCredential is returned, wrapped in a *NoMatchingCredentialError, when no
// supplied credential opens any recipient stanza.
var ErrNoMatchingCredential = errors.New("archive: no matching credential")

// NoMatchingCredentialError reports which kinds of credential an archive accepts when
// none of the supplied ones opened it. Kinds are public in the recipient block.
type NoMatchingCredentialError struct {
	Accepts []string
}

func (e *NoMatchingCredentialError) Error() string {
	return fmt.Sprintf("%v (archive accepts: %s)", ErrNoMatchingCredential, strings.Join(e.Accepts, ", "))
}

// Is reports target == ErrNoMatchingCredential.
func (e *NoMatchingCredentialError) Is(target error) bool { return target == ErrNoMatchingCredential }

// ErrMalformedRecipientBlock is returned when a recipient block cannot be parsed.
var ErrMalformedRecipientBlock = errors.New("archive: malformed recipient block")

// Credentials lists who can open an archive. Any one of them unlocks it in full.
type Credentials struct {
	Passwords     []string
	KeyFiles      []KeyFile
	AgeRecipients []age.Recipient
}

// KeyFile is a key file credential. When Password is set, the key file and the
// password are one credential and both are needed to open the archive.
type KeyFile struct {
	Key      []byte
	Password string
}

// Unlockers lists the secrets a reader tries against an archive's recipient block.
type Unlockers struct {
	Password   string // empty means no password
	KeyFiles   [][]byte
	Identities []age.Identity
}

// SealRecipientBlock wraps cek for every credential in creds and returns the encoded block.
func SealRecipientBlock(cek [crypto.KeySize]byte, creds Credentials) ([]byte, error) {
	if len(creds.Passwords) == 0 && len(creds.KeyFiles) == 0 && len(creds.AgeRecipients) == 0 {
		return nil, fmt.Errorf("archive/recipients: at least one password, key file, or age recipient is required")
	}
	if len(creds.Passwords) > MaxPasswordRecipients {
		return nil, fmt.Errorf("archive/recipients: %d password recipients, maximum %d", len(creds.Passwords), MaxPasswordRecipients)
	}
	if len(creds.KeyFiles) > MaxKeyFileRecipients {
		return nil, fmt.Errorf("archive/recipients: %d key file recipients, maximum %d", len(creds.KeyFiles), MaxKeyFileRecipients)
	}

	count := len(creds.Passwords) + len(creds.KeyFiles)
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
	for _, kf := range creds.KeyFiles {
		kind, body, err := wrapForKeyFile(cek, kf)
		if err != nil {
			return nil, err
		}
		block = appendStanza(block, kind, body)
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

// wrapForKeyFile returns the stanza type and body wrapping cek for kf.
func wrapForKeyFile(cek [crypto.KeySize]byte, kf KeyFile) (byte, []byte, error) {
	if kf.Password == "" {
		w, err := crypto.WrapCEKWithKeyFile(cek, kf.Key)
		if err != nil {
			return 0, nil, fmt.Errorf("archive/recipients: wrap for key file: %w", err)
		}
		return stanzaTypeKeyFile, encodeKeyFileWrap(w), nil
	}
	w, err := crypto.WrapCEKWithKeyFileAndPassword(cek, kf.Key, kf.Password)
	if err != nil {
		return 0, nil, fmt.Errorf("archive/recipients: wrap for key file and password: %w", err)
	}
	return stanzaTypeKeyFilePassword, encodePasswordWrap(w), nil
}

// OpenRecipientBlock returns the CEK from the first stanza that u can open. Each stanza
// is tried only when u holds every credential it needs. When nothing matches it returns
// the *crypto.IdentityError of an identity that could not be used if there was one, and a *NoMatchingCredentialError otherwise.
func OpenRecipientBlock(block []byte, u Unlockers) ([crypto.KeySize]byte, error) {
	stanzas, err := parseRecipientBlock(block)
	if err != nil {
		return [crypto.KeySize]byte{}, err
	}
	var identityErr *crypto.IdentityError
	for _, s := range stanzas {
		var cek [crypto.KeySize]byte
		switch {
		case s.kind == stanzaTypePassword && u.Password != "":
			cek, err = crypto.UnwrapCEKWithPassword(decodePasswordWrap(s.body), u.Password)
		case s.kind == stanzaTypeAge && len(u.Identities) > 0:
			cek, err = crypto.UnwrapCEKWithAge(s.body, u.Identities)
		case s.kind == stanzaTypeKeyFile && len(u.KeyFiles) > 0:
			cek, err = crypto.UnwrapCEKWithKeyFile(decodeKeyFileWrap(s.body), u.KeyFiles)
		case s.kind == stanzaTypeKeyFilePassword && len(u.KeyFiles) > 0 && u.Password != "":
			cek, err = crypto.UnwrapCEKWithKeyFileAndPassword(decodePasswordWrap(s.body), u.KeyFiles, u.Password)
		default:
			continue
		}
		switch {
		case err == nil:
			return cek, nil
		case errors.As(err, &identityErr):
			// Keep trying the other stanzas; report it only if none opens.
		case !errors.Is(err, crypto.ErrWrongCredential):
			return [crypto.KeySize]byte{}, fmt.Errorf("%w: %w", ErrMalformedRecipientBlock, err)
		}
	}
	if identityErr != nil {
		return [crypto.KeySize]byte{}, identityErr
	}
	return [crypto.KeySize]byte{}, &NoMatchingCredentialError{Accepts: acceptedKinds(stanzas)}
}

// stanzaKindNames are the user-facing names of the credential each stanza type needs.
var stanzaKindNames = map[byte]string{
	stanzaTypePassword:        "password",
	stanzaTypeAge:             "age or SSH identity",
	stanzaTypeKeyFile:         "key file",
	stanzaTypeKeyFilePassword: "key file + password",
}

// acceptedKinds lists the distinct credential kinds in stanzas, in block order.
func acceptedKinds(stanzas []stanza) []string {
	var kinds []string
	seen := make(map[byte]bool, len(stanzaKindNames))
	for _, s := range stanzas {
		if !seen[s.kind] {
			seen[s.kind] = true
			kinds = append(kinds, stanzaKindNames[s.kind])
		}
	}
	return kinds
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
// fixed stanza sizes, at most MaxPasswordRecipients password stanzas,
// MaxKeyFileRecipients key file stanzas of each kind, and one age stanza, no trailing
// bytes, and at least one stanza.
func parseRecipientBlock(block []byte) ([]stanza, error) {
	if len(block) < 2 {
		return nil, fmt.Errorf("%w: truncated count", ErrMalformedRecipientBlock)
	}
	count := int(binary.LittleEndian.Uint16(block))
	if count == 0 || count > maxStanzas {
		return nil, fmt.Errorf("%w: %d stanzas", ErrMalformedRecipientBlock, count)
	}
	stanzas := make([]stanza, 0, count)
	perKind := make(map[byte]int, len(stanzaKindNames))
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
		perKind[kind]++
		if err := validateStanza(kind, len(body), perKind[kind]); err != nil {
			return nil, err
		}
		stanzas = append(stanzas, stanza{kind: kind, body: body})
	}
	if off != len(block) {
		return nil, fmt.Errorf("%w: trailing bytes", ErrMalformedRecipientBlock)
	}
	return stanzas, nil
}

// validateStanza checks a stanza's body length and that its kind, seen n times so far,
// stays within its limit.
func validateStanza(kind byte, bodyLen, n int) error {
	var ok bool
	switch kind {
	case stanzaTypePassword:
		ok = bodyLen == passwordStanzaSize && n <= MaxPasswordRecipients
	case stanzaTypeAge:
		ok = bodyLen > 0 && n == 1
	case stanzaTypeKeyFile:
		ok = bodyLen == keyFileStanzaSize && n <= MaxKeyFileRecipients
	case stanzaTypeKeyFilePassword:
		ok = bodyLen == passwordStanzaSize && n <= MaxKeyFileRecipients
	default:
		return fmt.Errorf("%w: unknown stanza type 0x%02x", ErrMalformedRecipientBlock, kind)
	}
	if !ok {
		return fmt.Errorf("%w: bad %s stanza", ErrMalformedRecipientBlock, stanzaKindNames[kind])
	}
	return nil
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

func encodeKeyFileWrap(w crypto.KeyFileWrap) []byte {
	b := make([]byte, 0, keyFileStanzaSize)
	b = append(b, w.Salt[:]...)
	b = append(b, w.Nonce[:]...)
	return append(b, w.Sealed[:]...)
}

// decodeKeyFileWrap expects a body already validated to keyFileStanzaSize bytes.
func decodeKeyFileWrap(b []byte) crypto.KeyFileWrap {
	var w crypto.KeyFileWrap
	off := copy(w.Salt[:], b)
	off += copy(w.Nonce[:], b[off:])
	copy(w.Sealed[:], b[off:])
	return w
}
