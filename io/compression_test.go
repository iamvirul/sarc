// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/iamvirul/sarc/archive"
)

func mustPolicy(t *testing.T, mode CompressionMode) *compressionPolicy {
	t.Helper()
	p, err := newCompressionPolicy(CompressionOptions{Mode: mode, Level: archive.DefaultCompressionLevel})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCodecForAutoMode(t *testing.T) {
	random := make([]byte, compressionProbeSize)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	text := bytes.Repeat([]byte("func main() { fmt.Println(\"hello\") }\n"), 2000)[:compressionProbeSize]

	cases := []struct {
		name  string
		file  string
		probe []byte
		want  archive.Codec
	}{
		{"compressible text", "main.go", text, archive.CodecZstd},
		{"random data", "data.bin", random, archive.CodecNone},
		{"empty file", "empty.txt", nil, archive.CodecNone},
		{"known compressed extension", "photo.jpg", text, archive.CodecNone},
		{"extension match is case-insensitive", "CLIP.MP4", text, archive.CodecNone},
		{"office zip container", "report.docx", text, archive.CodecNone},
	}
	p := mustPolicy(t, CompressionAuto)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.codecFor(tc.file, tc.probe); got != tc.want {
				t.Fatalf("codecFor(%q) = %v, want %v", tc.file, got, tc.want)
			}
		})
	}
}

func TestCodecForAlwaysIgnoresContentAndExtension(t *testing.T) {
	p := mustPolicy(t, CompressionAlways)
	if got := p.codecFor("photo.jpg", nil); got != archive.CodecZstd {
		t.Fatalf("got %v, want zstd", got)
	}
}

func TestCodecForNeverIgnoresContent(t *testing.T) {
	p := mustPolicy(t, CompressionNever)
	if got := p.codecFor("main.go", bytes.Repeat([]byte("a"), 4096)); got != archive.CodecNone {
		t.Fatalf("got %v, want none", got)
	}
	if p.compressor != nil {
		t.Fatal("never mode built a compressor")
	}
}

func TestNewCompressionPolicyRejectsInvalidOptions(t *testing.T) {
	if _, err := newCompressionPolicy(CompressionOptions{Mode: CompressionAuto, Level: 0}); !errors.Is(err, archive.ErrInvalidCompressionLevel) {
		t.Fatalf("level 0: want ErrInvalidCompressionLevel, got %v", err)
	}
	if _, err := newCompressionPolicy(CompressionOptions{Mode: CompressionMode(99), Level: 3}); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestNewCompressionPolicyNeverIgnoresLevel(t *testing.T) {
	if _, err := newCompressionPolicy(CompressionOptions{Mode: CompressionNever, Level: 0}); err != nil {
		t.Fatalf("never mode should not validate level: %v", err)
	}
}

func TestArchiverRejectsInvalidCompressionOptions(t *testing.T) {
	opt := WithCompression(CompressionOptions{Mode: CompressionAlways, Level: archive.MaxCompressionLevel + 1})
	var ae *ArchiveError

	_, err := NewStreamingArchiver(&bytes.Buffer{}, "invalid-options", nil, opt)
	if !errors.As(err, &ae) || ae.Code != ErrCodeInvalidOption {
		t.Fatalf("streaming: want %s, got %v", ErrCodeInvalidOption, err)
	}
	_, err = NewConcurrentArchiver(&bytes.Buffer{}, "invalid-options", 2, nil, opt)
	if !errors.As(err, &ae) || ae.Code != ErrCodeInvalidOption {
		t.Fatalf("concurrent: want %s, got %v", ErrCodeInvalidOption, err)
	}
}

func TestOnlyAutoModeBuildsProbeCompressor(t *testing.T) {
	if mustPolicy(t, CompressionAuto).probeCompressor == nil {
		t.Fatal("auto mode has no probe compressor")
	}
	for _, mode := range []CompressionMode{CompressionAlways, CompressionNever} {
		if mustPolicy(t, mode).probeCompressor != nil {
			t.Fatalf("%v mode built an unused probe compressor", mode)
		}
	}
}
