// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"golang.org/x/crypto/pbkdf2"
)

// A content-encryption key (CEK) is the random per-archive master key. It is never
// derived from a credential; each recipient instead holds a wrapped copy of it.

const (
	// MinPasswordIterations and MaxPasswordIterations bound the PBKDF2 cost a password
	// wrap may declare: the floor keeps brute force expensive, the ceiling stops a
	// hostile archive from forcing an unbounded key derivation.
	MinPasswordIterations = PBKDF2Iter
	MaxPasswordIterations = 10_000_000
	// passwordWrapAAD binds a password wrap to its purpose.
	passwordWrapAAD = "sarc password recipient"
)

// ErrWrongCredential is returned when a password or identity does not unwrap a CEK.
var ErrWrongCredential = errors.New("crypto/cek: credential does not match")

// IdentityError reports an identity that failed for a reason other than not matching,
// such as a wrong SSH key passphrase or a missing or cancelled age plugin.
type IdentityError struct {
	Err error
}

func (e *IdentityError) Error() string { return "crypto/cek: identity failed: " + e.Err.Error() }

func (e *IdentityError) Unwrap() error { return e.Err }

// PasswordWrap is a CEK sealed with AES-256-GCM under PBKDF2-SHA256(password, Salt, Iterations).
type PasswordWrap struct {
	Iterations uint32
	Salt       [SaltSize]byte
	Nonce      [NonceSize]byte
	Sealed     [KeySize + GCMTagSize]byte
}

// GenerateCEK returns a random content-encryption key from crypto/rand.
func GenerateCEK() ([KeySize]byte, error) {
	var cek [KeySize]byte
	if _, err := rand.Read(cek[:]); err != nil {
		return cek, fmt.Errorf("crypto/cek: generate: %w", err)
	}
	return cek, nil
}

// WrapCEKWithPassword seals cek under a key derived from password with a fresh salt
// and nonce, at MinPasswordIterations.
func WrapCEKWithPassword(cek [KeySize]byte, password string) (PasswordWrap, error) {
	w := PasswordWrap{Iterations: MinPasswordIterations}
	if err := randomSaltAndNonce(&w.Salt, &w.Nonce); err != nil {
		return PasswordWrap{}, err
	}
	aead, err := passwordAEAD(password, w.Salt, w.Iterations)
	if err != nil {
		return PasswordWrap{}, err
	}
	aead.Seal(w.Sealed[:0], w.Nonce[:], cek[:], []byte(passwordWrapAAD))
	return w, nil
}

// UnwrapCEKWithPassword opens w with password. It returns ErrWrongCredential when the
// password does not match, and an error without deriving a key when w declares an
// iteration count outside [MinPasswordIterations, MaxPasswordIterations].
func UnwrapCEKWithPassword(w PasswordWrap, password string) ([KeySize]byte, error) {
	var cek [KeySize]byte
	if w.Iterations < MinPasswordIterations || w.Iterations > MaxPasswordIterations {
		return cek, fmt.Errorf("crypto/cek: password wrap iterations %d out of range", w.Iterations)
	}
	aead, err := passwordAEAD(password, w.Salt, w.Iterations)
	if err != nil {
		return cek, err
	}
	if _, err := aead.Open(cek[:0], w.Nonce[:], w.Sealed[:], []byte(passwordWrapAAD)); err != nil {
		return [KeySize]byte{}, ErrWrongCredential
	}
	return cek, nil
}

func randomSaltAndNonce(salt *[SaltSize]byte, nonce *[NonceSize]byte) error {
	if _, err := rand.Read(salt[:]); err != nil {
		return fmt.Errorf("crypto/cek: generate salt: %w", err)
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("crypto/cek: generate nonce: %w", err)
	}
	return nil
}

func passwordAEAD(password string, salt [SaltSize]byte, iterations uint32) (cipher.AEAD, error) {
	return newWrapAEAD(stretchPassword(password, salt, iterations))
}

// stretchPassword returns PBKDF2-SHA256(password, salt, iterations).
func stretchPassword(password string, salt [SaltSize]byte, iterations uint32) []byte {
	return pbkdf2.Key([]byte(password), salt[:], int(iterations), KeySize, sha256.New)
}

// newWrapAEAD returns AES-256-GCM keyed with a key-encryption key.
func newWrapAEAD(kek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("crypto/cek: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto/cek: new GCM: %w", err)
	}
	return aead, nil
}

// WrapCEKForAge encrypts cek to every recipient as a standard age file, so any age
// identity matching one recipient can recover it. age stanzas carry only ephemeral
// shares, not recipient public keys.
func WrapCEKForAge(cek [KeySize]byte, recipients []age.Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("crypto/cek: no age recipients")
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("crypto/cek: age encrypt: %w", err)
	}
	if _, err := w.Write(cek[:]); err != nil {
		return nil, fmt.Errorf("crypto/cek: age write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("crypto/cek: age close: %w", err)
	}
	return buf.Bytes(), nil
}

// UnwrapCEKWithAge decrypts an age file produced by WrapCEKForAge. It returns
// ErrWrongCredential when none of identities matches a recipient, and an
// *IdentityError when an identity itself fails.
func UnwrapCEKWithAge(blob []byte, identities []age.Identity) ([KeySize]byte, error) {
	var cek [KeySize]byte
	if len(identities) == 0 {
		return cek, ErrWrongCredential
	}
	var identityErr error
	r, err := age.Decrypt(bytes.NewReader(blob), recordIdentityFailures(identities, &identityErr)...)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		switch {
		case errors.As(err, &noMatch):
			return cek, ErrWrongCredential
		case identityErr != nil:
			return cek, &IdentityError{Err: identityErr}
		}
		return cek, fmt.Errorf("crypto/cek: age decrypt: %w", err)
	}
	// Read one byte past the key to reject a payload of the wrong length.
	plain, err := io.ReadAll(io.LimitReader(r, KeySize+1))
	if err != nil {
		return cek, fmt.Errorf("crypto/cek: age read: %w", err)
	}
	if len(plain) != KeySize {
		return cek, fmt.Errorf("crypto/cek: age payload is %d bytes, want %d", len(plain), KeySize)
	}
	copy(cek[:], plain)
	return cek, nil
}

// recordIdentityFailures wraps each non-native identity (SSH keys, plugins) so that a
// failure other than ErrIncorrectIdentity is stored in *failure. Native identities fail
// only on malformed stanzas and stay unwrapped, which also keeps age trying them first.
func recordIdentityFailures(identities []age.Identity, failure *error) []age.Identity {
	wrapped := make([]age.Identity, len(identities))
	for i, id := range identities {
		switch id.(type) {
		case *age.X25519Identity, *age.HybridIdentity, *age.ScryptIdentity:
			wrapped[i] = id
		default:
			wrapped[i] = recordingIdentity{Identity: id, failure: failure}
		}
	}
	return wrapped
}

type recordingIdentity struct {
	age.Identity
	failure *error
}

func (r recordingIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	fileKey, err := r.Identity.Unwrap(stanzas)
	if err != nil && !errors.Is(err, age.ErrIncorrectIdentity) {
		*r.failure = err
	}
	return fileKey, err
}
