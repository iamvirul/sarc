// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/iamvirul/sarc/crypto"
)

const (
	interBlockPadMin = 256
	interBlockPadMax = 1024
	blockVariance    = 8 * 1024
)

// FrameBuilder assembles the on-disk layout for a single file entry.
type FrameBuilder struct {
	em      *crypto.EncryptionManager
	padding *crypto.PaddingManager
	varGen  crypto.VarianceGenerator
}

// NewFrameBuilder returns a FrameBuilder for a specific file key.
func NewFrameBuilder(key [crypto.KeySize]byte) (*FrameBuilder, error) {
	em, err := crypto.NewEncryptionManager(key)
	if err != nil {
		return nil, fmt.Errorf("archive/frames: init encryption: %w", err)
	}
	return &FrameBuilder{
		em:      em,
		padding: crypto.NewPaddingManager(),
		varGen:  crypto.NewRandomVarianceGenerator(blockVariance),
	}, nil
}

// RandomFrameHeader returns a 32-byte random opaque header.
func RandomFrameHeader() (FrameHeader, error) {
	var fh FrameHeader
	if _, err := rand.Read(fh[:]); err != nil {
		return fh, fmt.Errorf("archive/frames: random frame header: %w", err)
	}
	return fh, nil
}

// InterBlockPadding returns random bytes in [interBlockPadMin, interBlockPadMax].
func (fb *FrameBuilder) InterBlockPadding() ([]byte, error) {
	pad, err := randomRange(interBlockPadMin, interBlockPadMax)
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
	cs, err := entryChecksum()
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

func entryChecksum() ([8]byte, error) {
	var cs [8]byte
	if _, err := rand.Read(cs[:]); err != nil {
		return cs, fmt.Errorf("archive/frames: entry checksum: %w", err)
	}
	return cs, nil
}

func randomRange(min, max int) ([]byte, error) {
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	size := min + (int(b[0])<<8|int(b[1]))%(max-min+1)
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}
