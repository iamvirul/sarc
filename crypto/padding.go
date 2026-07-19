package crypto

import (
	"crypto/rand"
	"fmt"
)

const (
	HeaderPadMin  = 1024
	HeaderPadMax  = 4096
	TrailerPadMin = 512
	TrailerPadMax = 2048
)

// PaddingManager generates cryptographically secure random padding.
// Padding is never reused across files; each call to Header/Trailer produces fresh bytes.
type PaddingManager struct{}

// NewPaddingManager returns a PaddingManager.
func NewPaddingManager() *PaddingManager {
	return &PaddingManager{}
}

// Header returns between HeaderPadMin and HeaderPadMax bytes of random data
// to prepend before encrypted file content.
func (pm *PaddingManager) Header() ([]byte, error) {
	return secureRandomRange(HeaderPadMin, HeaderPadMax)
}

// Trailer returns between TrailerPadMin and TrailerPadMax bytes of random data
// to append after encrypted file content.
func (pm *PaddingManager) Trailer() ([]byte, error) {
	return secureRandomRange(TrailerPadMin, TrailerPadMax)
}

// Bytes returns exactly n cryptographically secure random bytes.
func Bytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("crypto/padding: requested size must be positive, got %d", n)
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("crypto/padding: generate %d bytes: %w", n, err)
	}
	return buf, nil
}

// secureRandomRange generates a random number of bytes in [min, max].
func secureRandomRange(min, max int) ([]byte, error) {
	span := max - min + 1
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto/padding: range select: %w", err)
	}
	size := min + (int(b[0])<<8|int(b[1]))%span
	return Bytes(size)
}
