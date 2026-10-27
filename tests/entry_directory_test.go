// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build linux || darwin

package tests_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/iamvirul/sarc/archive"
	sarcio "github.com/iamvirul/sarc/io"
)

const entryDirectoryPassword = "entry-directory-password"

// directoryTree builds a tree with every entry kind, a compressible file, and a
// random file spanning many data blocks.
func directoryTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	metadataTree(t, root)
	data := filepath.Join(root, "data")
	random := make([]byte, 3<<20)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "random.bin"), random, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "text.log"), bytes.Repeat([]byte("log line\n"), 20000), 0o644); err != nil {
		t.Fatal(err)
	}
	return data
}

func buildDirectoryArchive(t *testing.T, src string, concurrent bool, opts ...sarcio.ArchiverOption) []byte {
	t.Helper()
	var buf bytes.Buffer
	if concurrent {
		ca, err := sarcio.NewConcurrentArchiver(&buf, entryDirectoryPassword, 4, nil, opts...)
		if err != nil {
			t.Fatal(err)
		}
		if err := ca.Archive([]string{src}); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	sa, err := sarcio.NewStreamingArchiver(&buf, entryDirectoryPassword, nil, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.AddFile(src); err != nil {
		t.Fatal(err)
	}
	if err := sa.Finalize(0, 0); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// listScan lists data by reading it sequentially, as from a pipe.
func listScan(t *testing.T, data []byte) []sarcio.ListResult {
	t.Helper()
	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), entryDirectoryPassword, nil).List()
	if err != nil {
		t.Fatal(err)
	}
	return results
}

// rangeRecorder is an io.ReaderAt that counts the bytes read through it.
type rangeRecorder struct {
	ra io.ReaderAt
	mu sync.Mutex
	n  int64
}

func (r *rangeRecorder) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.ra.ReadAt(p, off)
	r.mu.Lock()
	r.n += int64(n)
	r.mu.Unlock()
	return n, err
}

// failingReader fails every read, proving the sequential reader is never used.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("sequential reader used") }

// listDirectory lists data through random access only and returns the bytes read.
func listDirectory(data []byte) ([]sarcio.ListResult, int64, error) {
	rec := &rangeRecorder{ra: bytes.NewReader(data)}
	ex := sarcio.NewSafeExtractor(failingReader{}, entryDirectoryPassword, nil,
		sarcio.WithRandomAccess(rec, int64(len(data))))
	results, err := ex.List()
	return results, rec.n, err
}

func TestDirectoryListingMatchesScan(t *testing.T) {
	src := directoryTree(t)
	for _, concurrent := range []bool{false, true} {
		for _, solid := range []bool{false, true} {
			opts := sarcio.CompressionOptions{Mode: sarcio.CompressionAuto, Level: archive.DefaultCompressionLevel, Solid: solid}
			data := buildDirectoryArchive(t, src, concurrent, sarcio.WithCompression(opts))
			want := listScan(t, data)
			got, _, err := listDirectory(data)
			if err != nil {
				t.Fatalf("concurrent=%v solid=%v: %v", concurrent, solid, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("concurrent=%v solid=%v: directory listing differs from scan:\n got %+v\nwant %+v",
					concurrent, solid, got, want)
			}
		}
	}
}

func TestDirectoryListingReadsNoDataBlocks(t *testing.T) {
	data := buildDirectoryArchive(t, directoryTree(t), true)
	_, read, err := listDirectory(data)
	if err != nil {
		t.Fatal(err)
	}
	// The header, tail, and directory each cost one buffered read; the 3 MiB of data
	// blocks are never read.
	if limit := int64(1 << 20); read > limit {
		t.Fatalf("listing read %d bytes of a %d-byte archive, want at most %d", read, len(data), limit)
	}
}

func TestDirectoryListingOfSignedArchive(t *testing.T) {
	data := buildDirectoryArchive(t, directoryTree(t), false, sarcio.WithSigner(newSSHSigner(t)))
	got, _, err := listDirectory(data)
	if err != nil {
		t.Fatal(err)
	}
	if want := listScan(t, data); !reflect.DeepEqual(got, want) {
		t.Fatal("signed archive: directory listing differs from scan")
	}
}

// directoryOffset returns the offset of data's directory entry from its locator.
func directoryOffset(t *testing.T, data []byte) int {
	t.Helper()
	start := len(data) - archive.DirectoryTailSize
	off, err := archive.ParseDirectoryLocator(data[start : start+archive.DirectoryLocatorSize])
	if err != nil {
		t.Fatal(err)
	}
	return int(off)
}

func TestTamperedDirectoryFailsListing(t *testing.T) {
	data := buildDirectoryArchive(t, directoryTree(t), true)
	off := directoryOffset(t, data)
	metadataNonce := off + 1 + archive.ReservedSize + archive.ReservedSize
	for name, at := range map[string]int{"entry type": off, "metadata": metadataNonce} {
		bad := bytes.Clone(data)
		bad[at] ^= 0x01
		_, _, err := listDirectory(bad)
		var ae *sarcio.ArchiveError
		if !errors.As(err, &ae) || ae.Code != sarcio.ErrCodeIntegrityFail {
			t.Errorf("%s: err = %v, want %s", name, err, sarcio.ErrCodeIntegrityFail)
		}
	}
}

func TestDirectoryLocatorOutsideArchiveFailsListing(t *testing.T) {
	data := bytes.Clone(buildDirectoryArchive(t, directoryTree(t), true))
	start := len(data) - archive.DirectoryTailSize
	copy(data[start:], archive.AppendDirectoryLocator(nil, uint64(start)))
	_, _, err := listDirectory(data)
	var ae *sarcio.ArchiveError
	if !errors.As(err, &ae) || ae.Code != sarcio.ErrCodeIntegrityFail {
		t.Fatalf("err = %v, want %s", err, sarcio.ErrCodeIntegrityFail)
	}
}
