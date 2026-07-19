// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	NonceSize     = 12
	GCMTagSize    = 16
	BaseBlockSize = 64 * 1024
)

// EncryptedBlock holds one AES-256-GCM encrypted chunk with its nonce.
// Nonce is stored plaintext; Ciphertext includes the 16-byte GCM auth tag.
type EncryptedBlock struct {
	Nonce      [NonceSize]byte
	Ciphertext []byte
}

// EncryptionManager performs AES-256-GCM block encryption with a derived key.
type EncryptionManager struct {
	gcm cipher.AEAD
}

// NewEncryptionManager returns an EncryptionManager keyed by a 32-byte AES-256 key.
func NewEncryptionManager(key [KeySize]byte) (*EncryptionManager, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("crypto/encryption: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto/encryption: new GCM: %w", err)
	}
	return &EncryptionManager{gcm: gcm}, nil
}

// EncryptBlock encrypts plaintext with a fresh random nonce.
func (em *EncryptionManager) EncryptBlock(plaintext []byte) (EncryptedBlock, error) {
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return EncryptedBlock{}, fmt.Errorf("crypto/encryption: generate nonce: %w", err)
	}
	return EncryptedBlock{
		Nonce:      nonce,
		Ciphertext: em.gcm.Seal(nil, nonce[:], plaintext, nil),
	}, nil
}

// DecryptBlock authenticates and decrypts a block. Returns an error if the GCM tag fails.
func (em *EncryptionManager) DecryptBlock(block EncryptedBlock) ([]byte, error) {
	pt, err := em.gcm.Open(nil, block.Nonce[:], block.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto/encryption: decrypt: authentication failed: %w", err)
	}
	return pt, nil
}

// EncryptStream reads r in variable-size chunks and returns the encrypted blocks.
// Chunk sizes vary around BaseBlockSize using varGen to prevent size-pattern analysis.
func (em *EncryptionManager) EncryptStream(r io.Reader, varGen VarianceGenerator) ([]EncryptedBlock, error) {
	var blocks []EncryptedBlock
	for {
		size := BaseBlockSize + varGen.Next()
		if size < 1 {
			size = 1
		}
		buf := make([]byte, size)
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			block, encErr := em.EncryptBlock(buf[:n])
			if encErr != nil {
				return nil, encErr
			}
			blocks = append(blocks, block)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("crypto/encryption: read stream: %w", err)
		}
	}
	return blocks, nil
}

// VarianceGenerator provides a per-chunk size delta (may be negative).
type VarianceGenerator interface {
	Next() int
}

// RandomVarianceGenerator returns a random delta in [-maxDelta, +maxDelta] per call.
type RandomVarianceGenerator struct {
	maxDelta int
}

// NewRandomVarianceGenerator returns a generator with variance up to maxDelta bytes.
func NewRandomVarianceGenerator(maxDelta int) *RandomVarianceGenerator {
	return &RandomVarianceGenerator{maxDelta: maxDelta}
}

// Next returns a cryptographically random delta in [-maxDelta, +maxDelta].
func (g *RandomVarianceGenerator) Next() int {
	if g.maxDelta == 0 {
		return 0
	}
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return 0
	}
	span := 2*g.maxDelta + 1
	return (int(b[0])<<8|int(b[1]))%span - g.maxDelta
}
