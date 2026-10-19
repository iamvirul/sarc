// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/iotest"

	"github.com/iamvirul/sarc/archive"
)

// fakeArchive returns body followed by a valid footer for it.
func fakeArchive(body []byte) []byte {
	sum := sha256.Sum256(body)
	out := append(append([]byte{}, body...), sum[:]...)
	return append(out, make([]byte, archive.ReservedSize)...)
}

func TestVerifyStreamAcceptsValidChecksum(t *testing.T) {
	body := bytes.Repeat([]byte("sarc body "), 300_000) // spans several verify chunks
	if ok, err := verifyStream(bytes.NewReader(fakeArchive(body))); err != nil || !ok {
		t.Fatalf("multi-chunk input: ok=%v err=%v", ok, err)
	}
	// One byte per Read exercises the footer holdback across many reads.
	ok, err := verifyStream(iotest.OneByteReader(bytes.NewReader(fakeArchive(body[:5000]))))
	if err != nil || !ok {
		t.Fatalf("one-byte reads: ok=%v err=%v", ok, err)
	}
}

func TestVerifyStreamRejectsCorruption(t *testing.T) {
	data := fakeArchive(bytes.Repeat([]byte{0x42}, 10_000))
	data[123] ^= 0x01
	if ok, err := verifyStream(bytes.NewReader(data)); err != nil || ok {
		t.Fatalf("corrupted body: ok=%v err=%v", ok, err)
	}
}

func TestVerifyStreamRejectsShortInput(t *testing.T) {
	short := make([]byte, archive.HMACSize+archive.ReservedSize-1)
	if _, err := verifyStream(bytes.NewReader(short)); !errors.Is(err, errArchiveTooSmall) {
		t.Fatalf("want errArchiveTooSmall, got %v", err)
	}
}

func TestVerifyStreamEmptyBody(t *testing.T) {
	if ok, err := verifyStream(bytes.NewReader(fakeArchive(nil))); err != nil || !ok {
		t.Fatalf("footer-only input: ok=%v err=%v", ok, err)
	}
}

func TestIsTerminalFalseForRegularFile(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "plain"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Fatal("regular file reported as a terminal")
	}
}

func TestCreateArchiveOutputFileSendsProgressToStdout(t *testing.T) {
	out, err := createArchiveOutput(filepath.Join(t.TempDir(), "a.sarc"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if out.file == nil || out.progress != os.Stdout {
		t.Fatal("file output should keep progress on stdout")
	}
}

func TestOpenArchiveInputMissingFile(t *testing.T) {
	if _, err := openArchiveInput(filepath.Join(t.TempDir(), "missing.sarc")); err == nil {
		t.Fatal("opened a missing archive")
	}
}
