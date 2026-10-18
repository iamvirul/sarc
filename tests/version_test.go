// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/iamvirul/sarc/archive"
	sarcio "github.com/iamvirul/sarc/io"
)

// v1FixturePath is a two-file archive written by sarc v1.1.0 (format Version1, one
// PBKDF2 run per file entry). It must remain extractable by every later release.
const (
	v1FixturePath     = "testdata/v1_multi.sarc"
	v1FixturePassword = "sarc-v1-fixture-password"
)

// versionOffset is the byte offset of the little-endian uint16 format version.
const versionOffset = len(archive.Magic)

var v1FixtureFiles = map[string]struct {
	sha256Hex string
	perm      os.FileMode
}{
	"small.txt": {"eeb3e83b7153668489d4fbfd46b45bfd0f5f16f2c32b6f88ace00c94ccf724ae", 0o644},
	"large.bin": {"73d175f9fd849f4dfcc774558efa73c3437a2d8fd4b4304afefd4a0aa47ec0ba", 0o600},
}

func readV1Fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(v1FixturePath)
	if err != nil {
		t.Fatalf("read v1 fixture: %v", err)
	}
	if v := binary.LittleEndian.Uint16(data[versionOffset:]); v != archive.Version1 {
		t.Fatalf("fixture version = %d, want %d", v, archive.Version1)
	}
	return data
}

func TestExtractVersion1ArchiveStillWorks(t *testing.T) {
	data := readV1Fixture(t)
	outDir := t.TempDir()

	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), v1FixturePassword, nil).Extract(outDir)
	if err != nil {
		t.Fatalf("extract v1 archive: %v", err)
	}
	if len(results) != len(v1FixtureFiles) {
		t.Fatalf("got %d results, want %d", len(results), len(v1FixtureFiles))
	}
	for _, r := range results {
		if !r.OK {
			t.Fatalf("v1 entry failed: %v", r.Err)
		}
		want, ok := v1FixtureFiles[r.Filename]
		if !ok {
			t.Fatalf("unexpected entry %q", r.Filename)
		}
		path := filepath.Join(outDir, r.Filename)
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(got)
		if hex.EncodeToString(sum[:]) != want.sha256Hex {
			t.Fatalf("%s: content hash mismatch", r.Filename)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want.perm {
			t.Fatalf("%s: perm = %v, want %v", r.Filename, info.Mode().Perm(), want.perm)
		}
	}
}

func TestListVersion1ArchiveStillWorks(t *testing.T) {
	data := readV1Fixture(t)

	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), v1FixturePassword, nil).List()
	if err != nil {
		t.Fatalf("list v1 archive: %v", err)
	}
	if len(results) != len(v1FixtureFiles) {
		t.Fatalf("got %d results, want %d", len(results), len(v1FixtureFiles))
	}
	for _, r := range results {
		if _, ok := v1FixtureFiles[r.Filename]; !ok {
			t.Fatalf("unexpected or undecryptable entry %q", r.Filename)
		}
	}
}

func TestExtractVersion1ArchiveWrongPasswordFails(t *testing.T) {
	data := readV1Fixture(t)

	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), "not-the-fixture-password", nil).Extract(t.TempDir())
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, r := range results {
		if r.OK {
			t.Fatal("wrong password produced a successful v1 extraction")
		}
	}
}

func TestNewArchivesUseCurrentVersion(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(src, []byte("current version"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	ca, err := sarcio.NewConcurrentArchiver(&buf, "version-check-pass", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Archive([]string{src}); err != nil {
		t.Fatal(err)
	}
	if v := binary.LittleEndian.Uint16(buf.Bytes()[versionOffset:]); v != archive.Version2 {
		t.Fatalf("new archive version = %d, want %d", v, archive.Version2)
	}
}

func TestExtractRejectsUnknownVersion(t *testing.T) {
	data := readV1Fixture(t)
	patched := append([]byte(nil), data...)
	binary.LittleEndian.PutUint16(patched[versionOffset:], archive.Version+1)

	_, err := sarcio.NewSafeExtractor(bytes.NewReader(patched), v1FixturePassword, nil).Extract(t.TempDir())
	var ae *sarcio.ArchiveError
	if !errors.As(err, &ae) || ae.Code != sarcio.ErrCodeBadVersion || !ae.IsFatal() {
		t.Fatalf("want fatal %s, got %v", sarcio.ErrCodeBadVersion, err)
	}
}

// TestVersion1ArchiveRelabelledAsVersion2Fails confirms the version field selects the
// key schedule: a v1 body cannot be decrypted with v2 keys, so a downgrade or
// upgrade of the version byte is detected rather than producing output.
func TestVersion1ArchiveRelabelledAsVersion2Fails(t *testing.T) {
	data := readV1Fixture(t)
	patched := append([]byte(nil), data...)
	binary.LittleEndian.PutUint16(patched[versionOffset:], archive.Version2)

	results, err := sarcio.NewSafeExtractor(bytes.NewReader(patched), v1FixturePassword, nil).Extract(t.TempDir())
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, r := range results {
		if r.OK {
			t.Fatal("v1 entry decrypted under v2 key schedule")
		}
	}
}

func TestMultiFileVersion2Roundtrip(t *testing.T) {
	dir := t.TempDir()
	const fileCount = 25
	paths := make([]string, fileCount)
	want := make(map[string][]byte, fileCount)
	for i := range paths {
		name := fmt.Sprintf("file-%02d.txt", i)
		content := bytes.Repeat([]byte{byte(i)}, 512+i*97)
		paths[i] = filepath.Join(dir, name)
		want[name] = content
		if err := os.WriteFile(paths[i], content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	ca, err := sarcio.NewConcurrentArchiver(&buf, "multi-file-v2-pass", 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Archive(paths); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "out")
	results, err := sarcio.NewSafeExtractor(bytes.NewReader(buf.Bytes()), "multi-file-v2-pass", nil).Extract(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != fileCount {
		t.Fatalf("got %d results, want %d", len(results), fileCount)
	}
	for _, r := range results {
		if !r.OK {
			t.Fatalf("entry failed: %v", r.Err)
		}
		got, err := os.ReadFile(filepath.Join(outDir, r.Filename))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want[r.Filename]) {
			t.Fatalf("%s: content mismatch", r.Filename)
		}
	}
}

// TestListMultiFileArchiveReturnsEveryEntry guards against the list path desynchronising
// on the trailer: List skips HMAC verification, and the entry checksum after the sealed
// HMAC must still be consumed so the next entry is parsed from the right offset.
func TestListMultiFileArchiveReturnsEveryEntry(t *testing.T) {
	dir := t.TempDir()
	names := []string{"one.txt", "two.txt", "three.txt"}
	paths := make([]string, len(names))
	for i, name := range names {
		paths[i] = filepath.Join(dir, name)
		if err := os.WriteFile(paths[i], bytes.Repeat([]byte(name), 100), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	ca, err := sarcio.NewConcurrentArchiver(&buf, "list-multi-pass", 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Archive(paths); err != nil {
		t.Fatal(err)
	}

	results, err := sarcio.NewSafeExtractor(bytes.NewReader(buf.Bytes()), "list-multi-pass", nil).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(names) {
		t.Fatalf("got %d entries, want %d", len(results), len(names))
	}
	for i, r := range results {
		if r.Filename != names[i] {
			t.Fatalf("entry %d: got %q, want %q", i, r.Filename, names[i])
		}
	}
}
