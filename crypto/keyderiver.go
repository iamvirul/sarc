// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	SaltSize   = 32
	KeySize    = 32
	PBKDF2Iter = 100_000
)

// KeyDeriver derives per-file AES-256 keys from a master password via PBKDF2-SHA256.
type KeyDeriver struct {
	password []byte
}

// NewKeyDeriver returns a KeyDeriver for the given master password.
func NewKeyDeriver(password string) *KeyDeriver {
	return &KeyDeriver{password: []byte(password)}
}

// GenerateSalt returns a cryptographically random 32-byte salt.
func GenerateSalt() ([SaltSize]byte, error) {
	var salt [SaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return salt, fmt.Errorf("crypto/keyderiver: generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKey returns a 32-byte AES-256 key from the master password and salt.
func (kd *KeyDeriver) DeriveKey(salt [SaltSize]byte) [KeySize]byte {
	raw := pbkdf2.Key(kd.password, salt[:], PBKDF2Iter, KeySize, sha256.New)
	var key [KeySize]byte
	copy(key[:], raw)
	return key
}
