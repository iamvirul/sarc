// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamvirul/sarc/crypto"
	sarcio "github.com/iamvirul/sarc/io"
)

const streamingTestPassword = "streaming-test-password"

// requireNoTempFiles fails if an extraction left any in-progress temporary file behind.
func requireNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".sarc-extract-") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

// archiveNever archives paths uncompressed, so data blocks map 1:1 to plaintext chunks.
func archiveNever(t *testing.T, paths ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	sa, err := sarcio.NewStreamingArchiver(&buf, streamingTestPassword, nil,
		sarcio.WithCompression(sarcio.CompressionOptions{Mode: sarcio.CompressionNever}))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if err := sa.AddFile(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := sa.Finalize(len(paths), 0); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// firstEntryBlocks returns the byte ranges of the first entry's data block records
// (nonce | size | ciphertext), in order.
func firstEntryBlocks(t *testing.T, data []byte) [][2]int {
	t.Helper()
	var blocks [][2]int
	off := firstBlockSizeOffset(t, data) - crypto.NonceSize
	for {
		size := int(binary.LittleEndian.Uint32(data[off+crypto.NonceSize:]))
		if size == 0 {
			return blocks
		}
		end := off + crypto.NonceSize + 4 + size
		blocks = append(blocks, [2]int{off, end})
		off = end
	}
}

func extractStreaming(t *testing.T, data []byte, outDir string) ([]sarcio.ExtractionResult, error) {
	t.Helper()
	return sarcio.NewSafeExtractor(bytes.NewReader(data), streamingTestPassword, nil).Extract(outDir)
}

// TestReorderedBlocksNeverReachTheFinalFile swaps the first two data blocks of an entry.
// Each block still authenticates on its own, so only the whole-file HMAC, checked after
// streaming, catches it: the file must not be published and no temp file may remain.
func TestReorderedBlocksNeverReachTheFinalFile(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.bin")
	if err := os.WriteFile(victim, randomContent(t, 3*1024*1024), 0o644); err != nil {
		t.Fatal(err)
	}
	data := archiveNever(t, victim)
	blocks := firstEntryBlocks(t, data)
	if len(blocks) < 2 {
		t.Fatalf("need at least 2 blocks, got %d", len(blocks))
	}
	a, b := blocks[0], blocks[1]
	swapped := append([]byte{}, data[:a[0]]...)
	swapped = append(swapped, data[b[0]:b[1]]...)
	swapped = append(swapped, data[a[0]:a[1]]...)
	swapped = append(swapped, data[b[1]:]...)

	outDir := filepath.Join(dir, "out")
	results, err := extractStreaming(t, swapped, outDir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	var ae *sarcio.ArchiveError
	if len(results) != 1 || results[0].OK || !errors.As(results[0].Err, &ae) || ae.Code != sarcio.ErrCodeIntegrityFail {
		t.Fatalf("want one %s result, got %+v", sarcio.ErrCodeIntegrityFail, results)
	}
	if _, err := os.Stat(filepath.Join(outDir, "victim.bin")); !os.IsNotExist(err) {
		t.Fatalf("reordered data was published: %v", err)
	}
	requireNoTempFiles(t, outDir)
}

func TestTamperedLargeEntryLeavesNoFileAndNextEntryExtracts(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "a-first.bin"), filepath.Join(dir, "b-second.txt")
	secondContent := compressibleText(64 * 1024)
	if err := os.WriteFile(first, randomContent(t, 2*1024*1024), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, secondContent, 0o644); err != nil {
		t.Fatal(err)
	}
	data := archiveNever(t, first, second)
	blocks := firstEntryBlocks(t, data)
	data[blocks[len(blocks)-1][0]+crypto.NonceSize+4+50] ^= 0xFF // corrupt the last block

	outDir := filepath.Join(dir, "out")
	results, err := extractStreaming(t, data, outDir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(results) != 2 || results[0].OK || !results[1].OK {
		t.Fatalf("want first failed and second OK, got %+v", results)
	}
	if _, err := os.Stat(filepath.Join(outDir, "a-first.bin")); !os.IsNotExist(err) {
		t.Fatalf("partially decrypted file was published: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "b-second.txt"))
	if err != nil || !bytes.Equal(got, secondContent) {
		t.Fatalf("second entry: %v", err)
	}
	requireNoTempFiles(t, outDir)
}

func TestTruncatedStreamLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(src, randomContent(t, 3*1024*1024), 0o644); err != nil {
		t.Fatal(err)
	}
	data := archiveNever(t, src)
	outDir := filepath.Join(dir, "out")
	_, err := extractStreaming(t, data[:len(data)/2], outDir)
	var ae *sarcio.ArchiveError
	if !errors.As(err, &ae) || !ae.IsFatal() || ae.Code != sarcio.ErrCodeTruncated {
		t.Fatalf("want fatal %s, got %v", sarcio.ErrCodeTruncated, err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "big.bin")); !os.IsNotExist(err) {
		t.Fatalf("truncated entry was published: %v", err)
	}
	requireNoTempFiles(t, outDir)
}

func TestExtractReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "doc.txt")
	content := compressibleText(10 * 1024)
	if err := os.WriteFile(src, content, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o640); err != nil {
		t.Fatal(err)
	}
	data := archiveNever(t, src)

	outDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(outDir, "doc.txt")
	if err := os.WriteFile(existing, []byte("stale contents that are longer than nothing"), 0o600); err != nil {
		t.Fatal(err)
	}
	results, err := extractStreaming(t, data, outDir)
	if err != nil || len(results) != 1 || !results[0].OK {
		t.Fatalf("extract failed: %v %+v", err, results)
	}
	got, err := os.ReadFile(existing)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("existing file not replaced: %v", err)
	}
	info, err := os.Stat(existing)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("perm %v, want 0640 (%v)", info.Mode().Perm(), err)
	}
	requireNoTempFiles(t, outDir)
}

// TestConcurrentArchiverKeepsOrderWithInlineLargeFiles mixes many small files with large
// ones, which the writer streams inline while workers run ahead on small files. Entries
// must still appear in submission order and roundtrip exactly.
func TestConcurrentArchiverKeepsOrderWithInlineLargeFiles(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	contents := make(map[string][]byte)
	for i := 0; i < 40; i++ {
		name := fmt.Sprintf("%02d-small.txt", i)
		size := 1000 + i*137
		if i%13 == 5 {
			name = fmt.Sprintf("%02d-large.bin", i)
			size = 5*1024*1024 + i
		}
		content := randomContent(t, size)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
		contents[name] = content
	}
	var buf bytes.Buffer
	ca, err := sarcio.NewConcurrentArchiver(&buf, streamingTestPassword, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Archive(paths); err != nil {
		t.Fatal(err)
	}

	listed, err := sarcio.NewSafeExtractor(bytes.NewReader(buf.Bytes()), streamingTestPassword, nil).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != len(paths) {
		t.Fatalf("listed %d entries, want %d", len(listed), len(paths))
	}
	for i, r := range listed {
		if want := filepath.Base(paths[i]); r.Filename != want {
			t.Fatalf("entry %d is %s, want %s", i, r.Filename, want)
		}
	}
	outDir := t.TempDir()
	results, err := extractStreaming(t, buf.Bytes(), outDir)
	if err != nil || len(results) != len(paths) {
		t.Fatalf("extract: %v (%d results)", err, len(results))
	}
	for name, want := range contents {
		got, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: content mismatch (%v)", name, err)
		}
	}
}
