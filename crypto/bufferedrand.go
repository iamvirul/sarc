// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto

import (
	crand "crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20"
)

// BufferedRand is a CSPRNG backed by a ChaCha20 keystream seeded once from crypto/rand.
// It eliminates per-block syscalls on the archive hot path: nonce generation, variance
// selection, and padding all read from an in-process keystream after the initial seed.
//
// Each instance must be used by a single goroutine. Create one per file entry.
type BufferedRand struct {
	stream *chacha20.Cipher
}

// NewBufferedRand seeds a ChaCha20 cipher from crypto/rand and returns a BufferedRand.
// Only one syscall is made: the 32-byte seed read.
func NewBufferedRand() (*BufferedRand, error) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(crand.Reader, seed); err != nil {
		return nil, fmt.Errorf("crypto/bufferedrand: seed: %w", err)
	}
	// Zero nonce is safe: key is never reused, so nonce uniqueness is guaranteed.
	nonce := make([]byte, chacha20.NonceSize)
	stream, err := chacha20.NewUnauthenticatedCipher(seed, nonce)
	if err != nil {
		return nil, fmt.Errorf("crypto/bufferedrand: new cipher: %w", err)
	}
	return &BufferedRand{stream: stream}, nil
}

// Read fills p with pseudorandom bytes derived from the ChaCha20 keystream.
// Never returns an error.
func (br *BufferedRand) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	br.stream.XORKeyStream(p, p)
	return len(p), nil
}
