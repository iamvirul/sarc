// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	sarcio "github.com/iamvirul/sarc/io"
)

const dedupPassword = "dedup-test-password"

// TestDeduplicationResistance archives the same file twice with the same password
// and asserts the two resulting archives are byte-for-byte different.
func TestDeduplicationResistance(t *testing.T) {
	dir := t.TempDir()
	content := bytes.Repeat([]byte("DUPLICATE CONTENT "), 1000)
	filePath := filepath.Join(dir, "same.bin")
	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	archive1 := archiveToBytes(t, filePath)
	archive2 := archiveToBytes(t, filePath)

	if bytes.Equal(archive1, archive2) {
		t.Fatal("two archives of the same file are byte-for-byte identical: deduplication resistance failed")
	}
}

// TestSameFileInSeparateArchivesDiffers archives the same file twice into different
// archives and confirms no 16-byte repeating block pattern exists across them.
func TestSameFileInSeparateArchivesDiffers(t *testing.T) {
	dir := t.TempDir()
	content := bytes.Repeat([]byte("PATTERN"), 2000)
	filePath := filepath.Join(dir, "pattern.bin")
	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatal(err)
	}

	a1 := archiveToBytes(t, filePath)
	a2 := archiveToBytes(t, filePath)

	// Scan for any identical 16-byte block at matching offsets between the two archives.
	limit := min(len(a1), len(a2))
	repeated := 0
	for i := 0; i+16 <= limit; i += 16 {
		if bytes.Equal(a1[i:i+16], a2[i:i+16]) {
			repeated++
		}
	}
	// Headers share Magic + Version bytes, so a small overlap is expected.
	// More than 2 identical 16-byte blocks at matching offsets is a red flag.
	if repeated > 2 {
		t.Fatalf("found %d identical 16-byte blocks at matching offsets across two archives", repeated)
	}
}

func archiveToBytes(t *testing.T, filePath string) []byte {
	t.Helper()
	var buf bytes.Buffer
	sa, err := sarcio.NewStreamingArchiver(&buf, dedupPassword, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.AddFile(filePath); err != nil {
		t.Fatal(err)
	}
	if err := sa.Finalize(1, 0); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
