// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// writeRandomFile creates a temp file of exactly size random bytes and returns it open
// for reading (caller must close and remove via t.Cleanup).
func writeRandomFile(t *testing.T, size int) *os.File {
	t.Helper()
	f, err := os.CreateTemp("", "sarc-mmap-test-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.Close()
		os.Remove(f.Name())
	})

	buf := make([]byte, 4<<20)
	remaining := size
	for remaining > 0 {
		n := len(buf)
		if remaining < n {
			n = remaining
		}
		if _, err := rand.Read(buf[:n]); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(buf[:n]); err != nil {
			t.Fatal(err)
		}
		remaining -= n
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestTryMmapBelowThresholdFallsBack verifies files under mmapThreshold are rejected by
// tryMmap so addFileStreaming takes the buffered-reader path instead.
func TestTryMmapBelowThresholdFallsBack(t *testing.T) {
	f := writeRandomFile(t, 1024)
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tryMmap(f, info.Size()); err == nil {
		t.Fatal("expected tryMmap to reject a file below mmapThreshold, got nil error")
	}
}

// TestTryMmapAboveThresholdSucceeds forces the mmap path (or its documented fallback on
// unsupported platforms) and verifies the mapped bytes match the file's real content.
func TestTryMmapAboveThresholdSucceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping mmap threshold test in -short mode")
	}

	f := writeRandomFile(t, mmapThreshold+1024)
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	mapped, err := tryMmap(f, info.Size())
	if err != nil {
		t.Fatalf("tryMmap on a file above mmapThreshold: %v", err)
	}
	defer mapped.close()

	if int64(len(mapped.data)) != info.Size() {
		t.Fatalf("mapped length = %d, want %d", len(mapped.data), info.Size())
	}

	want, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mapped.data, want) {
		t.Fatal("mapped bytes do not match file content")
	}
}

// TestEncryptAndStreamMmapMatchesBuffered forces both the mmap path and the buffered
// path over identical content and verifies they decrypt to identical plaintext with
// identical HMACs, proving the mmap I/O-path optimisation has no effect on correctness.
func TestEncryptAndStreamMmapMatchesBuffered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping mmap-vs-buffered equivalence test in -short mode")
	}

	f := writeRandomFile(t, mmapThreshold+512*1024)
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	key := crypto.NewKeyDeriver("mmap-equivalence-test").DeriveKey(salt)

	// mmap path.
	fbMmap, err := archive.NewFrameBuilder(key)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := tryMmap(f, info.Size())
	if err != nil {
		t.Fatalf("tryMmap: %v", err)
	}
	var mmapBlocks []archive.DataBlock
	mmapHMAC, err := encryptAndStreamMmap(mapped.data, fbMmap, key, 4, NopProgressTracker{}, func(db archive.DataBlock) error {
		// Copy out: the pipeline reuses db's backing buffer as soon as send()
		// returns (safe for real callers, which write the bytes out immediately;
		// this test instead holds onto blocks for later inspection).
		mmapBlocks = append(mmapBlocks, copyDataBlock(db))
		return nil
	})
	if err != nil {
		t.Fatalf("encryptAndStreamMmap: %v", err)
	}
	if err := mapped.close(); err != nil {
		t.Fatal(err)
	}

	// Buffered path, same key so ciphertexts aren't expected to match (independent
	// nonces/padding), but decrypted plaintext and HMAC must.
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	fbBuf, err := archive.NewFrameBuilder(key)
	if err != nil {
		t.Fatal(err)
	}
	var bufBlocks []archive.DataBlock
	bufHMAC, err := encryptAndStreamParallel(f, fbBuf, key, 4, func(db archive.DataBlock) error {
		bufBlocks = append(bufBlocks, copyDataBlock(db))
		return nil
	})
	if err != nil {
		t.Fatalf("encryptAndStreamParallel: %v", err)
	}

	if mmapHMAC != bufHMAC {
		t.Fatalf("HMAC mismatch: mmap %x buffered %x", mmapHMAC, bufHMAC)
	}

	em, err := crypto.NewEncryptionManager(key)
	if err != nil {
		t.Fatal(err)
	}
	mmapPlain := decryptBlocksForTest(t, em, mmapBlocks)
	bufPlain := decryptBlocksForTest(t, em, bufBlocks)

	mmapSum := sha256.Sum256(mmapPlain)
	bufSum := sha256.Sum256(bufPlain)
	if mmapSum != bufSum {
		t.Fatal("mmap and buffered paths decrypted to different plaintext")
	}

	want, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	wantSum := sha256.Sum256(want)
	if mmapSum != wantSum {
		t.Fatal("decrypted plaintext does not match the original file")
	}
}

// copyDataBlock deep-copies a DataBlock's ciphertext. The parallel pipelines reuse a
// block's backing buffer as soon as send() returns, so a test that wants to inspect
// blocks after the pipeline call has finished must copy them out first.
func copyDataBlock(db archive.DataBlock) archive.DataBlock {
	ct := make([]byte, len(db.Ciphertext))
	copy(ct, db.Ciphertext)
	return archive.DataBlock{Nonce: db.Nonce, Ciphertext: ct}
}

func decryptBlocksForTest(t *testing.T, em *crypto.EncryptionManager, blocks []archive.DataBlock) []byte {
	t.Helper()
	var out bytes.Buffer
	for i, b := range blocks {
		pt, err := em.DecryptBlock(crypto.EncryptedBlock{Nonce: b.Nonce, Ciphertext: b.Ciphertext})
		if err != nil {
			t.Fatalf("decrypt block %d: %v", i, err)
		}
		out.Write(pt)
	}
	return out.Bytes()
}

// TestAddFileStreamingRoundtripAboveThreshold forces addFileStreaming through the mmap
// path end to end (archive then extract via SafeExtractor) and checks a byte-perfect
// round trip, exercising the exact path StreamingArchiver.AddFile and
// ConcurrentArchiver's single-file fast path use, both uncompressed and zstd-compressed.
func TestAddFileStreamingRoundtripAboveThreshold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping mmap end-to-end roundtrip in -short mode")
	}

	f := writeRandomFile(t, mmapThreshold+2048)
	want, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	wantSum := sha256.Sum256(want)

	for _, mode := range []CompressionMode{CompressionNever, CompressionAlways} {
		t.Run(mode.String(), func(t *testing.T) {
			policy, err := newCompressionPolicy(CompressionOptions{Mode: mode, Level: archive.DefaultCompressionLevel})
			if err != nil {
				t.Fatal(err)
			}

			var archiveBuf bytes.Buffer
			aw, err := archive.NewArchiveWriter(&archiveBuf, archive.Credentials{Passwords: []string{"mmap-roundtrip-pass"}})
			if err != nil {
				t.Fatal(err)
			}
			if err := aw.WriteHeader(0); err != nil {
				t.Fatal(err)
			}
			if _, err := addFileStreaming(aw, policy, inputFile{path: f.Name(), name: filepath.Base(f.Name()), attrs: archive.Attributes{Mode: 0o644}}, 4, NopProgressTracker{}); err != nil {
				t.Fatalf("addFileStreaming: %v", err)
			}
			if err := aw.WriteFooter(); err != nil {
				t.Fatal(err)
			}

			outDir := t.TempDir()
			ex := NewSafeExtractor(bytes.NewReader(archiveBuf.Bytes()), "mmap-roundtrip-pass", nil)
			results, err := ex.Extract(outDir)
			if err != nil {
				t.Fatalf("extract: %v", err)
			}
			if len(results) != 1 || !results[0].OK {
				var extractErr error
				if len(results) == 1 {
					extractErr = results[0].Err
				}
				t.Fatalf("extraction failed: %v", extractErr)
			}

			extracted, err := os.ReadFile(filepath.Join(outDir, results[0].Filename))
			if err != nil {
				t.Fatal(err)
			}
			gotSum := sha256.Sum256(extracted)
			if gotSum != wantSum {
				t.Fatal("SHA-256 mismatch after mmap-path archive/extract roundtrip")
			}
		})
	}
}
