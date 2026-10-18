// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/klauspost/compress/zstd"
)

// Codec identifies how a file entry's data-block payloads are encoded before encryption.
// It is stored per file in the sealed metadata (Version2+); Version1 entries are always CodecNone.
type Codec uint8

const (
	// CodecNone stores each block's plaintext as-is.
	CodecNone Codec = 0
	// CodecZstd stores each block as one independent zstd frame of its plaintext.
	CodecZstd Codec = 1
)

// String returns the codec name shown to users.
func (c Codec) String() string {
	switch c {
	case CodecNone:
		return "none"
	case CodecZstd:
		return "zstd"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(c))
	}
}

// Compression level bounds, using zstd's 1-22 scale.
const (
	MinCompressionLevel     = 1
	MaxCompressionLevel     = 22
	DefaultCompressionLevel = 3
)

const (
	// zstdWindowSize is the smallest power of two that covers MaxChunkSize, so every
	// block is a single-window frame and encoder/decoder memory stays bounded.
	zstdWindowSize = 512 * 1024
	// zstdMaxOverhead bounds frame header plus raw-block headers zstd adds to an
	// incompressible MaxChunkSize input (checksums are disabled; GCM authenticates).
	zstdMaxOverhead = 256
	// bestTierMaxEncoders caps concurrent encoders at the best-compression tier, where
	// each encoder holds roughly 35 MB of state. Uncapped, GOMAXPROCS of them push peak
	// memory past several hundred MB.
	bestTierMaxEncoders = 2
)

// MaxPayloadSize is the largest encoded block payload (before the GCM tag) a writer emits.
const MaxPayloadSize = MaxChunkSize + zstdMaxOverhead

// ErrInvalidCompressionLevel is returned for a level outside [MinCompressionLevel, MaxCompressionLevel].
var ErrInvalidCompressionLevel = errors.New("archive: invalid compression level")

// ErrBlockTooLarge is returned when a block decodes to more than MaxChunkSize bytes.
var ErrBlockTooLarge = errors.New("archive: decoded block exceeds maximum chunk size")

// BlockCompressor zstd-encodes data-block plaintext. Safe for concurrent use.
type BlockCompressor struct {
	enc *zstd.Encoder
}

// NewBlockCompressor returns a BlockCompressor for a zstd level in [1, 22]. The level is
// mapped to the nearest encoder tier supported by the pure-Go implementation.
func NewBlockCompressor(level int) (*BlockCompressor, error) {
	if level < MinCompressionLevel || level > MaxCompressionLevel {
		return nil, fmt.Errorf("%w: %d (want %d-%d)", ErrInvalidCompressionLevel, level, MinCompressionLevel, MaxCompressionLevel)
	}
	encLevel := zstd.EncoderLevelFromZstd(level)
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(encLevel),
		zstd.WithEncoderConcurrency(encoderConcurrency(encLevel)),
		zstd.WithEncoderCRC(false),
		zstd.WithWindowSize(zstdWindowSize),
	)
	if err != nil {
		return nil, fmt.Errorf("archive/codec: new zstd encoder: %w", err)
	}
	return &BlockCompressor{enc: enc}, nil
}

// encoderConcurrency returns how many encoders may run at once for level: GOMAXPROCS,
// capped at bestTierMaxEncoders for the memory-hungry best-compression tier.
func encoderConcurrency(level zstd.EncoderLevel) int {
	n := runtime.GOMAXPROCS(0)
	if level >= zstd.SpeedBestCompression {
		return min(n, bestTierMaxEncoders)
	}
	return n
}

// Compress appends one zstd frame of src to dst and returns the extended slice.
// When cap(dst) >= len(dst)+len(src)+zstdMaxOverhead it does not allocate.
func (bc *BlockCompressor) Compress(dst, src []byte) []byte {
	return bc.enc.EncodeAll(src, dst)
}

// BlockDecompressor decodes zstd block payloads. Safe for concurrent use.
// Close must be called to release decoder resources.
type BlockDecompressor struct {
	dec *zstd.Decoder
}

// NewBlockDecompressor returns a BlockDecompressor that rejects any frame decoding
// to more than MaxChunkSize bytes, bounding memory against hostile payloads.
func NewBlockDecompressor() (*BlockDecompressor, error) {
	dec, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(runtime.GOMAXPROCS(0)),
		zstd.WithDecoderMaxMemory(MaxChunkSize),
		zstd.WithDecoderMaxWindow(zstdWindowSize),
	)
	if err != nil {
		return nil, fmt.Errorf("archive/codec: new zstd decoder: %w", err)
	}
	return &BlockDecompressor{dec: dec}, nil
}

// Decompress decodes one block payload produced by BlockCompressor.Compress.
func (bd *BlockDecompressor) Decompress(src []byte) ([]byte, error) {
	out, err := bd.dec.DecodeAll(src, nil)
	if err != nil {
		if errors.Is(err, zstd.ErrDecoderSizeExceeded) || errors.Is(err, zstd.ErrWindowSizeExceeded) ||
			errors.Is(err, zstd.ErrFrameSizeExceeded) {
			return nil, ErrBlockTooLarge
		}
		return nil, fmt.Errorf("archive/codec: zstd decode: %w", err)
	}
	if len(out) > MaxChunkSize {
		return nil, ErrBlockTooLarge
	}
	return out, nil
}

// Close releases the decoder's resources. The BlockDecompressor must not be used afterwards.
func (bd *BlockDecompressor) Close() {
	bd.dec.Close()
}
