package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	SaltSize       = 32
	KeySize        = 32
	PBKDF2Iter     = 100_000
)

// KeyDeriver derives per-file AES-256 keys from a master password using PBKDF2-SHA256.
type KeyDeriver struct {
	password []byte
}

// NewKeyDeriver creates a KeyDeriver from the given master password.
func NewKeyDeriver(password string) *KeyDeriver {
	return &KeyDeriver{password: []byte(password)}
}

// GenerateSalt returns a cryptographically secure random 32-byte salt.
func GenerateSalt() ([SaltSize]byte, error) {
	var salt [SaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return salt, fmt.Errorf("crypto/keyderiver: generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKey produces a 32-byte AES-256 key from the master password and the provided salt.
// Each unique salt yields an independent key, ensuring no cross-file key correlation.
func (kd *KeyDeriver) DeriveKey(salt [SaltSize]byte) [KeySize]byte {
	raw := pbkdf2.Key(kd.password, salt[:], PBKDF2Iter, KeySize, sha256.New)
	var key [KeySize]byte
	copy(key[:], raw)
	return key
}
