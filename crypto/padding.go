// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto

import (
	crand "crypto/rand"
	"fmt"
	"io"
)

const (
	HeaderPadMin  = 1024
	HeaderPadMax  = 4096
	TrailerPadMin = 512
	TrailerPadMax = 2048
)

// PaddingManager generates cryptographically random padding. Each call produces fresh bytes.
type PaddingManager struct {
	rand io.Reader
}

// NewPaddingManager returns a PaddingManager that draws randomness from crypto/rand.
func NewPaddingManager() *PaddingManager { return &PaddingManager{rand: crand.Reader} }

// NewPaddingManagerWithRand returns a PaddingManager that draws randomness from r.
func NewPaddingManagerWithRand(r io.Reader) *PaddingManager { return &PaddingManager{rand: r} }

// Header returns [HeaderPadMin, HeaderPadMax] random bytes for prepending before file content.
func (pm *PaddingManager) Header() ([]byte, error) {
	return pm.secureRandomRange(HeaderPadMin, HeaderPadMax)
}

// Trailer returns [TrailerPadMin, TrailerPadMax] random bytes for appending after file content.
func (pm *PaddingManager) Trailer() ([]byte, error) {
	return pm.secureRandomRange(TrailerPadMin, TrailerPadMax)
}

// Bytes returns n cryptographically random bytes drawn from crypto/rand.
func Bytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("crypto/padding: n must be positive, got %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(crand.Reader, buf); err != nil {
		return nil, fmt.Errorf("crypto/padding: rand.Read %d bytes: %w", n, err)
	}
	return buf, nil
}

// secureRandomRange returns a random-length byte slice in [min, max] using pm.rand.
func (pm *PaddingManager) secureRandomRange(min, max int) ([]byte, error) {
	b := make([]byte, 2)
	if _, err := io.ReadFull(pm.rand, b); err != nil {
		return nil, fmt.Errorf("crypto/padding: range select: %w", err)
	}
	size := min + (int(b[0])<<8|int(b[1]))%(max-min+1)
	buf := make([]byte, size)
	if _, err := io.ReadFull(pm.rand, buf); err != nil {
		return nil, fmt.Errorf("crypto/padding: rand.Read %d bytes: %w", size, err)
	}
	return buf, nil
}
