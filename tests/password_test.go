// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/iamvirul/sarc/archive"
	sarcio "github.com/iamvirul/sarc/io"
)

const singleEntryPassword = "single-entry-test-password"

// archiveOneFile returns a single-entry archive of a small file named name.
func archiveOneFile(t *testing.T, name string) []byte {
	t.Helper()
	src := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(src, []byte("single entry payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	sa, err := sarcio.NewStreamingArchiver(&buf, singleEntryPassword, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.AddFile(src); err != nil {
		t.Fatal(err)
	}
	if err := sa.Finalize(1, 0); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// requireFatal fails the test unless err is a fatal ArchiveError with the given code.
func requireFatal(t *testing.T, err error, code string) {
	t.Helper()
	var ae *sarcio.ArchiveError
	if !errors.As(err, &ae) || ae.Code != code || !ae.IsFatal() {
		t.Fatalf("want fatal %s, got %v", code, err)
	}
}

// TestVersion2WrongPasswordFailsAtHeader confirms a wrong password is rejected by the
// sealed header file count before any entry is parsed or any output is written.
func TestVersion2WrongPasswordFailsAtHeader(t *testing.T) {
	data := archiveOneFile(t, "one.txt")
	outDir := filepath.Join(t.TempDir(), "out")

	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), "not-the-password", nil).Extract(outDir)
	requireFatal(t, err, sarcio.ErrCodeAuthFailed)
	if len(results) != 0 {
		t.Fatalf("got %d results, want none", len(results))
	}
	if _, statErr := os.Stat(outDir); !os.IsNotExist(statErr) {
		t.Fatalf("output directory created despite wrong password: %v", statErr)
	}

	_, err = sarcio.NewSafeExtractor(bytes.NewReader(data), "not-the-password", nil).List()
	requireFatal(t, err, sarcio.ErrCodeAuthFailed)
}

func TestVersion2TamperedHeaderFileCountFails(t *testing.T) {
	data := archiveOneFile(t, "one.txt")
	// The sealed file count sits just before the reserved bytes at the end of the header.
	data[archiveHeaderSize(data)-archive.ReservedSize-archive.FileCountSealedSize+20] ^= 0xFF

	_, err := sarcio.NewSafeExtractor(bytes.NewReader(data), singleEntryPassword, nil).Extract(t.TempDir())
	requireFatal(t, err, sarcio.ErrCodeAuthFailed)
}
