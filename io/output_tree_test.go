// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/iamvirul/sarc/archive"
)

// craftArchive writes an archive whose entries are given directly, bypassing the
// walker, so tests can build hostile combinations of links and files.
func craftArchive(t *testing.T, src string, entries []inputFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	aw, err := archive.NewArchiveWriter(&buf, archive.Credentials{Passwords: []string{"tree-test"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteHeader(0); err != nil {
		t.Fatal(err)
	}
	policy := mustPolicy(t, CompressionNever)
	for _, in := range entries {
		var entry archive.FileEntry
		if in.regular() {
			in.path = src
			entry, _, err = encryptFile(in, aw, policy, NopProgressTracker{})
		} else {
			entry, err = sealSpecialEntry(aw, in)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := aw.WriteFileEntry(entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := aw.WriteFooter(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func regularEntry(name string) inputFile {
	return inputFile{name: name, attrs: archive.Attributes{Mode: 0o644}}
}

func symlinkEntry(name, target string) inputFile {
	return inputFile{name: name, attrs: archive.Attributes{Kind: archive.KindSymlink, Mode: 0o777, LinkTarget: target}}
}

func extractCrafted(t *testing.T, data []byte, out string) []ExtractionResult {
	t.Helper()
	results, err := NewSafeExtractor(bytes.NewReader(data), "tree-test", nil).Extract(out)
	if err != nil {
		t.Fatal(err)
	}
	return results
}

func skipWithoutSymlinks(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
}

// TestSymlinkCannotRedirectALaterWrite archives a symlink pointing outside the output
// directory followed by a file "through" it: the file must not land outside.
func TestSymlinkCannotRedirectALaterWrite(t *testing.T) {
	skipWithoutSymlinks(t)
	src := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(src, []byte("pwned"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	data := craftArchive(t, src, []inputFile{
		symlinkEntry("evil", outside),
		symlinkEntry("rel", "../../.."),
		regularEntry("evil/pwned.txt"),
		regularEntry("rel/pwned.txt"),
		regularEntry("safe.txt"),
	})
	out := filepath.Join(t.TempDir(), "out")
	results := extractCrafted(t, data, out)
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("a write escaped through a symlink: %v", entries)
	}
	ok := map[string]bool{}
	for _, r := range results {
		ok[r.Filename] = r.OK
	}
	if !ok["safe.txt"] || ok["evil/pwned.txt"] || ok["rel/pwned.txt"] {
		t.Fatalf("results: %+v", results)
	}
}

// TestExistingSymlinkInOutputIsNotFollowed checks a symlink already in the output
// directory cannot redirect an entry outside it.
func TestExistingSymlinkInOutputIsNotFollowed(t *testing.T) {
	skipWithoutSymlinks(t)
	src := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(src, []byte("pwned"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	out := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(out, "dir")); err != nil {
		t.Fatal(err)
	}
	extractCrafted(t, craftArchive(t, src, []inputFile{regularEntry("dir/x.txt")}), out)
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("a write escaped through an existing symlink: %v", entries)
	}
}

// TestHardlinkToEscapingSymlinkStaysInside links to a symlink that points outside:
// the hard link is to the symlink itself, and replacing it never touches the outside.
func TestHardlinkToEscapingSymlinkStaysInside(t *testing.T) {
	skipWithoutSymlinks(t)
	src := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(src, []byte("pwned"), 0o644); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outsideFile, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	data := craftArchive(t, src, []inputFile{
		symlinkEntry("s", outsideFile),
		{name: "h", attrs: archive.Attributes{Kind: archive.KindHardlink, Mode: 0o644, LinkTarget: "s"}},
		regularEntry("h"),
	})
	extractCrafted(t, data, filepath.Join(t.TempDir(), "out"))
	if got, _ := os.ReadFile(outsideFile); string(got) != "original" {
		t.Fatalf("outside file changed to %q", got)
	}
}

func TestModeHelpers(t *testing.T) {
	for _, mode := range []uint32{0, 0o644, 0o755, 0o4755, 0o2750, 0o1777, 0o7777} {
		if got := unixMode(fileMode(mode)); got != mode {
			t.Fatalf("mode %o roundtrips to %o", mode, got)
		}
	}
}
