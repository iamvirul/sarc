// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"fmt"
	"io"

	"github.com/iamvirul/sarc/crypto"
)

const (
	interBlockPadMin = 256
	interBlockPadMax = 1024
	// BlockVariance is the maximum per-block size delta applied by the variance generator.
	BlockVariance = 32 * 1024
	// MaxChunkSize is the largest plaintext chunk the pipeline reader needs to buffer.
	MaxChunkSize = crypto.BaseBlockSize + BlockVariance
)

// FrameBuilder assembles the on-disk layout for a single file entry.
// A single BufferedRand is seeded once from crypto/rand and supplies all
// randomness needed for nonces, variance, padding, and structural fields.
type FrameBuilder struct {
	em      *crypto.EncryptionManager
	padding *crypto.PaddingManager
	varGen  crypto.VarianceGenerator
	br      *crypto.BufferedRand
}

// NewFrameBuilder returns a FrameBuilder for a specific file key.
// One BufferedRand is seeded from crypto/rand; all per-block random reads
// are served from its ChaCha20 keystream with no further syscalls.
func NewFrameBuilder(key [crypto.KeySize]byte) (*FrameBuilder, error) {
	br, err := crypto.NewBufferedRand()
	if err != nil {
		return nil, fmt.Errorf("archive/frames: buffered rand: %w", err)
	}
	em, err := crypto.NewEncryptionManagerWithRand(key, br)
	if err != nil {
		return nil, fmt.Errorf("archive/frames: init encryption: %w", err)
	}
	return &FrameBuilder{
		em:      em,
		padding: crypto.NewPaddingManagerWithRand(br),
		varGen:  crypto.NewRandomVarianceGeneratorWithRand(BlockVariance, br),
		br:      br,
	}, nil
}

// NextChunkSize returns the byte count the pipeline reader should fill for the next block.
// Draws from the per-file variance generator; must be called on the same goroutine that
// will call EncryptChunk so that the shared BufferedRand is not accessed concurrently.
func (fb *FrameBuilder) NextChunkSize() int {
	size := crypto.BaseBlockSize + fb.varGen.Next()
	if size < 1 {
		size = 1
	}
	return size
}

// EncryptChunk encrypts a single plaintext chunk and returns a DataBlock.
// Intended for the pipeline path; the caller manages chunking via NextChunkSize.
func (fb *FrameBuilder) EncryptChunk(plaintext []byte) (DataBlock, error) {
	b, err := fb.em.EncryptBlock(plaintext)
	if err != nil {
		return DataBlock{}, fmt.Errorf("archive/frames: encrypt chunk: %w", err)
	}
	return DataBlock{Nonce: b.Nonce, Ciphertext: b.Ciphertext}, nil
}

// EncryptChunkInto encrypts plaintext into dst without allocating.
// dst must have cap >= len(plaintext)+crypto.GCMTagSize. DataBlock.Ciphertext
// is a sub-slice of dst; callers must not return dst to a pool until after
// the DataBlock has been written to the archive.
func (fb *FrameBuilder) EncryptChunkInto(plaintext, dst []byte) (DataBlock, error) {
	b, err := fb.em.EncryptBlockInto(plaintext, dst)
	if err != nil {
		return DataBlock{}, fmt.Errorf("archive/frames: encrypt chunk: %w", err)
	}
	return DataBlock{Nonce: b.Nonce, Ciphertext: b.Ciphertext}, nil
}

// FrameHeader returns a 32-byte random opaque header drawn from the per-file CSPRNG.
func (fb *FrameBuilder) FrameHeader() (FrameHeader, error) {
	var fh FrameHeader
	if _, err := io.ReadFull(fb.br, fh[:]); err != nil {
		return fh, fmt.Errorf("archive/frames: frame header: %w", err)
	}
	return fh, nil
}

// InterBlockPadding returns random bytes in [interBlockPadMin, interBlockPadMax].
func (fb *FrameBuilder) InterBlockPadding() ([]byte, error) {
	pad, err := fb.randomRange(interBlockPadMin, interBlockPadMax)
	if err != nil {
		return nil, fmt.Errorf("archive/frames: inter-block padding: %w", err)
	}
	return pad, nil
}

// EncryptStream reads r in variable-length chunks and returns encrypted DataBlocks.
func (fb *FrameBuilder) EncryptStream(r io.Reader) ([]DataBlock, error) {
	blocks, err := fb.em.EncryptStream(r, fb.varGen)
	if err != nil {
		return nil, fmt.Errorf("archive/frames: encrypt stream: %w", err)
	}
	result := make([]DataBlock, len(blocks))
	for i, b := range blocks {
		result[i] = DataBlock{Nonce: b.Nonce, Ciphertext: b.Ciphertext}
	}
	return result, nil
}

// BuildTrailer constructs the FileTrailer, sealing plaintextHMAC with the file key.
func (fb *FrameBuilder) BuildTrailer(plaintextHMAC [crypto.HMACSize]byte) (FileTrailer, error) {
	pad, err := fb.padding.Trailer()
	if err != nil {
		return FileTrailer{}, fmt.Errorf("archive/frames: trailer padding: %w", err)
	}
	sealed, err := fb.em.EncryptBlock(plaintextHMAC[:])
	if err != nil {
		return FileTrailer{}, fmt.Errorf("archive/frames: seal HMAC: %w", err)
	}
	cs, err := fb.entryChecksum()
	if err != nil {
		return FileTrailer{}, fmt.Errorf("archive/frames: entry checksum: %w", err)
	}
	return FileTrailer{
		RandomPadding:       pad,
		PlaintextHMACNonce:  sealed.Nonce,
		PlaintextHMACSealed: sealed.Ciphertext,
		EntryChecksum:       cs,
	}, nil
}

// BuildHeaderPadding returns random header padding in [HeaderPadMin, HeaderPadMax].
func (fb *FrameBuilder) BuildHeaderPadding() ([]byte, error) {
	pad, err := fb.padding.Header()
	if err != nil {
		return nil, fmt.Errorf("archive/frames: header padding: %w", err)
	}
	return pad, nil
}

func (fb *FrameBuilder) entryChecksum() ([8]byte, error) {
	var cs [8]byte
	if _, err := io.ReadFull(fb.br, cs[:]); err != nil {
		return cs, fmt.Errorf("archive/frames: entry checksum: %w", err)
	}
	return cs, nil
}

func (fb *FrameBuilder) randomRange(min, max int) ([]byte, error) {
	b := make([]byte, 2)
	if _, err := io.ReadFull(fb.br, b); err != nil {
		return nil, err
	}
	size := min + (int(b[0])<<8|int(b[1]))%(max-min+1)
	buf := make([]byte, size)
	if _, err := io.ReadFull(fb.br, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
