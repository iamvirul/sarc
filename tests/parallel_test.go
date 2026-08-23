// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	sarcio "github.com/iamvirul/sarc/io"
)

const parallelTestPassword = "parallel-pipeline-pass"

// TestSingleFileConcurrentArchiverRoundtripAcrossGOMAXPROCS verifies that archiving a
// single large file through ConcurrentArchiver (the CLI's default archiver) round-trips
// byte-for-byte at GOMAXPROCS = 1, 2, 4, 8. ConcurrentArchiver only parallelises across
// files, so a single-file archive exercises the intra-file parallel block encryption
// path added for #21 instead of the cross-file worker pool.
func TestSingleFileConcurrentArchiverRoundtripAcrossGOMAXPROCS(t *testing.T) {
	dir := t.TempDir()
	content := make([]byte, 6*1024*1024+1234) // above minParallelFileSize
	if _, err := rand.Read(content); err != nil {
		t.Fatalf("generate content: %v", err)
	}
	wantSum := sha256.Sum256(content)

	src := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}

	prevGOMAXPROCS := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(prevGOMAXPROCS) })

	for _, procs := range []int{1, 2, 4, 8} {
		runtime.GOMAXPROCS(procs)

		var archiveBuf bytes.Buffer
		ca, err := sarcio.NewConcurrentArchiver(&archiveBuf, parallelTestPassword, 0, nil)
		if err != nil {
			t.Fatalf("GOMAXPROCS=%d: new concurrent archiver: %v", procs, err)
		}
		if err := ca.Archive([]string{src}); err != nil {
			t.Fatalf("GOMAXPROCS=%d: archive: %v", procs, err)
		}

		outDir := filepath.Join(dir, "out", fmt.Sprintf("gomaxprocs-%d", procs))
		ex := sarcio.NewSafeExtractor(bytes.NewReader(archiveBuf.Bytes()), parallelTestPassword, nil)
		results, err := ex.Extract(outDir)
		if err != nil {
			t.Fatalf("GOMAXPROCS=%d: extract: %v", procs, err)
		}
		if len(results) != 1 || !results[0].OK {
			var extractErr error
			if len(results) == 1 {
				extractErr = results[0].Err
			}
			t.Fatalf("GOMAXPROCS=%d: extraction failed: %v", procs, extractErr)
		}

		extracted, err := os.ReadFile(filepath.Join(outDir, "big.bin"))
		if err != nil {
			t.Fatalf("GOMAXPROCS=%d: read extracted: %v", procs, err)
		}
		gotSum := sha256.Sum256(extracted)
		if gotSum != wantSum {
			t.Fatalf("GOMAXPROCS=%d: SHA-256 mismatch: want %x got %x", procs, wantSum, gotSum)
		}
	}
}

// TestSingleFileConcurrentArchiverMemoryBound verifies that archiving one large file
// through the parallel intra-file path with 8 workers does not require loading the
// whole file into memory beyond a small, fixed multiple of the block size, by checking
// runtime.MemStats heap growth stays well under the 200 MB acceptance ceiling.
func TestSingleFileConcurrentArchiverMemoryBound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory-bound check in -short mode")
	}

	dir := t.TempDir()
	const size = 64 * 1024 * 1024
	src := filepath.Join(dir, "large.bin")
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4<<20)
	remaining := int64(size)
	for remaining > 0 {
		n := int64(len(buf))
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
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	archivePath := filepath.Join(dir, "large.sarc")
	archiveFile, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	ca, err := sarcio.NewConcurrentArchiver(archiveFile, parallelTestPassword, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Archive([]string{src}); err != nil {
		t.Fatal(err)
	}
	if err := archiveFile.Close(); err != nil {
		t.Fatal(err)
	}

	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	const ceiling = 200 * 1024 * 1024
	grew := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if grew > ceiling {
		t.Fatalf("heap grew by %d bytes archiving a %d-byte file with 8 workers, exceeding %d-byte ceiling", grew, size, ceiling)
	}
}
