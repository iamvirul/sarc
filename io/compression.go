// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// CompressionMode selects when file entries are zstd-compressed before encryption.
type CompressionMode uint8

const (
	// CompressionAuto compresses a file when a probe of its first bytes shrinks enough,
	// skipping known already-compressed formats by extension.
	CompressionAuto CompressionMode = iota
	// CompressionAlways compresses every file.
	CompressionAlways
	// CompressionNever stores every file uncompressed.
	CompressionNever
)

// String returns the mode name used in CLI flags and logs.
func (m CompressionMode) String() string {
	switch m {
	case CompressionAuto:
		return "auto"
	case CompressionAlways:
		return "always"
	case CompressionNever:
		return "never"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(m))
	}
}

const (
	// compressionProbeSize is how many leading bytes CompressionAuto test-compresses.
	compressionProbeSize = 64 * 1024
	// compressionMinSavingsPercent is the minimum probe size reduction for CompressionAuto
	// to compress a file; below this, zstd costs CPU for a negligible size win.
	compressionMinSavingsPercent = 5
)

// incompressibleExtensions lists formats that are already compressed, so CompressionAuto
// stores them as-is without spending CPU on a probe.
var incompressibleExtensions = map[string]struct{}{
	".jpg": {}, ".jpeg": {}, ".png": {}, ".gif": {}, ".webp": {}, ".heic": {}, ".avif": {},
	".mp4": {}, ".m4v": {}, ".mov": {}, ".mkv": {}, ".webm": {}, ".avi": {},
	".mp3": {}, ".m4a": {}, ".aac": {}, ".ogg": {}, ".opus": {}, ".flac": {},
	".zip": {}, ".gz": {}, ".tgz": {}, ".bz2": {}, ".xz": {}, ".zst": {}, ".7z": {}, ".rar": {},
	".jar": {}, ".apk": {}, ".docx": {}, ".xlsx": {}, ".pptx": {}, ".woff2": {}, ".sarc": {},
}

// CompressionOptions configures compression for an archiver.
type CompressionOptions struct {
	Mode  CompressionMode
	Level int // zstd level, archive.MinCompressionLevel..archive.MaxCompressionLevel
}

// DefaultCompressionOptions returns CompressionAuto at archive.DefaultCompressionLevel.
func DefaultCompressionOptions() CompressionOptions {
	return CompressionOptions{Mode: CompressionAuto, Level: archive.DefaultCompressionLevel}
}

// ArchiverOption configures a StreamingArchiver or ConcurrentArchiver.
type ArchiverOption func(*archiverConfig)

type archiverConfig struct {
	compression CompressionOptions
}

// WithCompression overrides the default compression options (CompressionAuto, level 3).
func WithCompression(opts CompressionOptions) ArchiverOption {
	return func(c *archiverConfig) { c.compression = opts }
}

// compressionPolicy decides the codec for each file. Safe for concurrent use.
type compressionPolicy struct {
	mode       CompressionMode
	compressor *archive.BlockCompressor // nil when mode is CompressionNever
	// probeCompressor runs CompressionAuto's test compression at the fastest level: the
	// probe only estimates compressibility, and a high-level encoder would cost tens of MB.
	probeCompressor *archive.BlockCompressor // nil unless mode is CompressionAuto
}

// newCompressionPolicy validates opts and builds the shared compressor.
func newCompressionPolicy(opts CompressionOptions) (*compressionPolicy, error) {
	switch opts.Mode {
	case CompressionNever:
		return &compressionPolicy{mode: opts.Mode}, nil
	case CompressionAuto, CompressionAlways:
		bc, err := archive.NewBlockCompressor(opts.Level)
		if err != nil {
			return nil, err
		}
		p := &compressionPolicy{mode: opts.Mode, compressor: bc}
		if opts.Mode == CompressionAuto {
			if p.probeCompressor, err = archive.NewBlockCompressor(archive.MinCompressionLevel); err != nil {
				return nil, err
			}
		}
		return p, nil
	default:
		return nil, fmt.Errorf("io/compression: unknown compression mode %d", opts.Mode)
	}
}

// newArchiverConfig applies opts over the defaults and builds the compression policy.
func newArchiverConfig(opts []ArchiverOption) (*compressionPolicy, error) {
	cfg := archiverConfig{compression: DefaultCompressionOptions()}
	for _, opt := range opts {
		opt(&cfg)
	}
	policy, err := newCompressionPolicy(cfg.compression)
	if err != nil {
		return nil, fatal(ErrCodeInvalidOption, "invalid compression options", err)
	}
	return policy, nil
}

// codecFor returns the codec for a file named name whose leading bytes are probe
// (at most compressionProbeSize; shorter for small files).
func (p *compressionPolicy) codecFor(name string, probe []byte) archive.Codec {
	switch p.mode {
	case CompressionAlways:
		return archive.CodecZstd
	case CompressionAuto:
		if _, skip := incompressibleExtensions[strings.ToLower(filepath.Ext(name))]; skip || len(probe) == 0 {
			return archive.CodecNone
		}
		compressed := p.probeCompressor.Compress(make([]byte, 0, len(probe)), probe)
		if len(compressed)*100 <= len(probe)*(100-compressionMinSavingsPercent) {
			return archive.CodecZstd
		}
		return archive.CodecNone
	default:
		return archive.CodecNone
	}
}

// newFrameBuilder returns a FrameBuilder applying codec under fileKey.
func (p *compressionPolicy) newFrameBuilder(fileKey [crypto.KeySize]byte, codec archive.Codec) (*archive.FrameBuilder, error) {
	if codec == archive.CodecZstd {
		return archive.NewCompressingFrameBuilder(fileKey, p.compressor)
	}
	return archive.NewFrameBuilder(fileKey)
}
