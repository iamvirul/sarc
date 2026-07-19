// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"

	sarcio "github.com/iamvirul/sarc/io"
)

const cliPassword = "cli-integration-pass"

// TestArchiveExtractRoundtrip archives a file, extracts it, and verifies SHA-256 matches.
func TestArchiveExtractRoundtrip(t *testing.T) {
	dir := t.TempDir()
	content := bytes.Repeat([]byte("roundtrip test data"), 500)
	src := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}

	var archiveBuf bytes.Buffer
	sa, err := sarcio.NewStreamingArchiver(&archiveBuf, cliPassword, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.AddFile(src); err != nil {
		t.Fatal(err)
	}
	if err := sa.Finalize(1, int64(len(content))); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "extracted")
	ex := sarcio.NewSafeExtractor(bytes.NewReader(archiveBuf.Bytes()), cliPassword, nil)
	results, err := ex.Extract(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].OK {
		t.Fatalf("extraction failed: %v", results[0].Err)
	}

	extracted, err := os.ReadFile(filepath.Join(outDir, "input.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if sha256sum(content) != sha256sum(extracted) {
		t.Fatal("SHA-256 mismatch between original and extracted file")
	}
}

// TestInvalidMagicRejected confirms that a byte stream with wrong magic is rejected.
func TestInvalidMagicRejected(t *testing.T) {
	bad := bytes.Repeat([]byte{0x00}, 256)
	ex := sarcio.NewSafeExtractor(bytes.NewReader(bad), cliPassword, nil)
	_, err := ex.Extract(t.TempDir())
	if err == nil {
		t.Fatal("expected error for invalid archive magic, got nil")
	}
}

// TestEmptyFileRoundtrip ensures a zero-byte file archives and extracts correctly.
func TestEmptyFileRoundtrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(src, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	sa, err := sarcio.NewStreamingArchiver(&buf, cliPassword, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.AddFile(src); err != nil {
		t.Fatal(err)
	}
	if err := sa.Finalize(1, 0); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "out")
	ex := sarcio.NewSafeExtractor(bytes.NewReader(buf.Bytes()), cliPassword, nil)
	results, err := ex.Extract(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || !results[0].OK {
		t.Fatal("empty file roundtrip failed")
	}
	got, _ := os.ReadFile(filepath.Join(outDir, "empty.txt"))
	if len(got) != 0 {
		t.Fatalf("expected empty file, got %d bytes", len(got))
	}
}

func sha256sum(data []byte) string {
	h := sha256.New()
	io.Copy(h, bytes.NewReader(data))
	return string(h.Sum(nil))
}
