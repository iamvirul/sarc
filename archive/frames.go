// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"encoding/binary"
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
	// TrailerPayloadSize is the sealed trailer plaintext: HMAC | plaintext size (uint64 LE).
	// Version1 trailers seal the HMAC alone.
	TrailerPayloadSize = HMACSize + 8
)

// FrameBuilder assembles the on-disk layout for a single file entry.
// A single BufferedRand is seeded once from crypto/rand and supplies all
// randomness needed for nonces, variance, padding, and structural fields.
// When compressor is set, every data-block method zstd-encodes the chunk before sealing.
type FrameBuilder struct {
	em         *crypto.EncryptionManager
	padding    *crypto.PaddingManager
	varGen     crypto.VarianceGenerator
	br         *crypto.BufferedRand
	compressor *BlockCompressor
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

// NewCompressingFrameBuilder returns a FrameBuilder for a CodecZstd entry: each data
// chunk is encoded as an independent zstd frame by bc, then sealed. bc may be shared
// across FrameBuilders and goroutines.
func NewCompressingFrameBuilder(key [crypto.KeySize]byte, bc *BlockCompressor) (*FrameBuilder, error) {
	if bc == nil {
		return nil, fmt.Errorf("archive/frames: nil block compressor")
	}
	fb, err := NewFrameBuilder(key)
	if err != nil {
		return nil, err
	}
	fb.compressor = bc
	return fb, nil
}

// Codec returns the codec this FrameBuilder applies to data blocks.
func (fb *FrameBuilder) Codec() Codec {
	if fb.compressor != nil {
		return CodecZstd
	}
	return CodecNone
}

// encodeInto returns the payload to seal for plaintext. For CodecNone it is plaintext
// itself; for CodecZstd it is a zstd frame written at the start of dst, so sealing it
// into dst afterwards is an exact in-place alias that AES-GCM permits.
func (fb *FrameBuilder) encodeInto(plaintext, dst []byte) []byte {
	if fb.compressor == nil {
		return plaintext
	}
	return fb.compressor.Compress(dst[:0], plaintext)
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

// EncryptChunk encodes and encrypts a single plaintext chunk and returns a DataBlock.
// Intended for the pipeline path; the caller manages chunking via NextChunkSize.
func (fb *FrameBuilder) EncryptChunk(plaintext []byte) (DataBlock, error) {
	if fb.compressor != nil {
		return fb.EncryptChunkInto(plaintext, make([]byte, 0, len(plaintext)+zstdMaxOverhead+crypto.GCMTagSize))
	}
	b, err := fb.em.EncryptBlock(plaintext)
	if err != nil {
		return DataBlock{}, fmt.Errorf("archive/frames: encrypt chunk: %w", err)
	}
	return DataBlock{Nonce: b.Nonce, Ciphertext: b.Ciphertext}, nil
}

// EncryptChunkInto encodes and encrypts plaintext into dst without allocating.
// dst must not overlap plaintext and must have cap >= len(plaintext)+crypto.GCMTagSize,
// or >= len(plaintext)+(MaxPayloadSize-MaxChunkSize)+crypto.GCMTagSize when compressing.
// DataBlock.Ciphertext is a sub-slice of dst; callers must not return dst to a pool
// until after the DataBlock has been written to the archive.
func (fb *FrameBuilder) EncryptChunkInto(plaintext, dst []byte) (DataBlock, error) {
	payload := fb.encodeInto(plaintext, dst)
	if fb.compressor != nil {
		dst = payload
	}
	b, err := fb.em.EncryptBlockInto(payload, dst)
	if err != nil {
		return DataBlock{}, fmt.Errorf("archive/frames: encrypt chunk: %w", err)
	}
	return DataBlock{Nonce: b.Nonce, Ciphertext: b.Ciphertext}, nil
}

// NextNonce draws the next 12-byte nonce from the per-file CSPRNG. Like NextChunkSize,
// it must be called only from the goroutine that owns this FrameBuilder's BufferedRand;
// pair it with EncryptChunkWithNonceInto to let the actual AES-GCM seal run on a worker
// goroutine while nonce generation stays single-threaded.
func (fb *FrameBuilder) NextNonce() ([crypto.NonceSize]byte, error) {
	var nonce [crypto.NonceSize]byte
	if _, err := io.ReadFull(fb.br, nonce[:]); err != nil {
		return nonce, fmt.Errorf("archive/frames: next nonce: %w", err)
	}
	return nonce, nil
}

// EncryptChunkWithNonceInto encodes and encrypts plaintext under a nonce obtained from
// NextNonce, writing into dst without allocating (same dst rules as EncryptChunkInto).
// Safe to call concurrently from multiple goroutines sharing this FrameBuilder, since it
// touches no FrameBuilder-owned mutable state and BlockCompressor is concurrency-safe.
func (fb *FrameBuilder) EncryptChunkWithNonceInto(nonce [crypto.NonceSize]byte, plaintext, dst []byte) DataBlock {
	payload := fb.encodeInto(plaintext, dst)
	if fb.compressor != nil {
		dst = payload
	}
	b := fb.em.EncryptBlockWithNonceInto(nonce, payload, dst)
	return DataBlock{Nonce: b.Nonce, Ciphertext: b.Ciphertext}
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

// EncryptStream reads r in variable-length chunks and returns encoded, encrypted DataBlocks.
func (fb *FrameBuilder) EncryptStream(r io.Reader) ([]DataBlock, error) {
	if fb.compressor != nil {
		return fb.encryptStreamCompressed(r)
	}
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

func (fb *FrameBuilder) encryptStreamCompressed(r io.Reader) ([]DataBlock, error) {
	var blocks []DataBlock
	buf := make([]byte, MaxChunkSize)
	for {
		n, err := io.ReadFull(r, buf[:fb.NextChunkSize()])
		if n > 0 {
			db, encErr := fb.EncryptChunk(buf[:n])
			if encErr != nil {
				return nil, encErr
			}
			blocks = append(blocks, db)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return blocks, nil
		}
		if err != nil {
			return nil, fmt.Errorf("archive/frames: read stream: %w", err)
		}
	}
}

// BuildTrailer constructs the FileTrailer, sealing plaintextHMAC and the total
// plaintext byte count with the file key (see TrailerPayloadSize).
func (fb *FrameBuilder) BuildTrailer(plaintextHMAC [crypto.HMACSize]byte, plaintextSize uint64) (FileTrailer, error) {
	pad, err := fb.padding.Trailer()
	if err != nil {
		return FileTrailer{}, fmt.Errorf("archive/frames: trailer padding: %w", err)
	}
	var payload [TrailerPayloadSize]byte
	copy(payload[:HMACSize], plaintextHMAC[:])
	binary.LittleEndian.PutUint64(payload[HMACSize:], plaintextSize)
	sealed, err := fb.em.EncryptBlock(payload[:])
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
