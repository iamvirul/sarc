// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/iamvirul/sarc/archive"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func storedNames(files []inputFile) []string {
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = f.name
	}
	return names
}

func TestExpandInputsStoresPathsRelativeToTheArgument(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"data/b.txt": "b", "data/a.txt": "a", "data/sub/deep/c.txt": "c", "data/.hidden": "h", "loose.txt": "l",
	})
	files, skipped := expandInputs([]string{filepath.Join(root, "data") + string(filepath.Separator), filepath.Join(root, "loose.txt")})
	if len(skipped) != 0 {
		t.Fatalf("unexpected skips: %+v", skipped)
	}
	want := []string{"data/.hidden", "data/a.txt", "data/b.txt", "data/sub/deep/c.txt", "loose.txt"}
	if got := storedNames(files); !equalStrings(got, want) {
		t.Fatalf("stored names %q, want %q", got, want)
	}
}

func TestExpandInputsDotDirectoryHasNoPrefix(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"a.txt": "a", "sub/b.txt": "b"})
	t.Chdir(root)
	files, _ := expandInputs([]string{"."})
	if got, want := storedNames(files), []string{"a.txt", "sub/b.txt"}; !equalStrings(got, want) {
		t.Fatalf("stored names %q, want %q", got, want)
	}
}

func TestExpandInputsSkipsSymlinksInsideDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{"data/real.txt": "r"})
	if err := os.Symlink("real.txt", filepath.Join(root, "data", "link.txt")); err != nil {
		t.Fatal(err)
	}
	files, skipped := expandInputs([]string{filepath.Join(root, "data")})
	if got := storedNames(files); !equalStrings(got, []string{"data/real.txt"}) {
		t.Fatalf("stored names %q", got)
	}
	if len(skipped) != 1 || filepath.Base(skipped[0].path) != "link.txt" {
		t.Fatalf("want the symlink skipped, got %+v", skipped)
	}
}

func TestExpandInputsReportsMissingArguments(t *testing.T) {
	files, skipped := expandInputs([]string{filepath.Join(t.TempDir(), "missing")})
	var ae *ArchiveError
	if len(files) != 0 || len(skipped) != 1 || !errors.As(skipped[0].err, &ae) || ae.IsFatal() {
		t.Fatalf("want one recoverable skip, got files %v skipped %+v", files, skipped)
	}
}

func TestEntryOutputPathRefusesEscapes(t *testing.T) {
	out := t.TempDir()
	for _, name := range []string{"../escape.txt", "/etc/passwd", "a/../../b", `..\b`, "", "dir/"} {
		if _, err := entryOutputPath(out, name); err == nil {
			t.Fatalf("%q accepted", name)
		}
	}
	got, err := entryOutputPath(out, "docs/2026/report.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(out, "docs", "2026", "report.pdf"); got != want {
		t.Fatalf("path %s, want %s", got, want)
	}
	if info, err := os.Stat(filepath.Dir(got)); err != nil || !info.IsDir() {
		t.Fatalf("parent directory not created: %v", err)
	}
}

// TestExtractRefusesTraversalNames writes entries whose stored names try to escape the
// output directory (bypassing expandInputs) and checks nothing lands outside it while
// the safe entry still extracts.
func TestExtractRefusesTraversalNames(t *testing.T) {
	src := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	aw, err := archive.NewArchiveWriter(&buf, archive.Credentials{Passwords: []string{"traversal-test"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteHeader(0); err != nil {
		t.Fatal(err)
	}
	policy := mustPolicy(t, CompressionNever)
	for _, name := range []string{"../escape.txt", "safe/ok.txt", "/abs.txt"} {
		entry, _, err := encryptFile(inputFile{path: src, name: name}, aw, policy, NopProgressTracker{})
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

	parent := t.TempDir()
	out := filepath.Join(parent, "out")
	results, err := NewSafeExtractor(&buf, "traversal-test", nil).Extract(out)
	if err != nil {
		t.Fatal(err)
	}
	var ok, failed int
	for _, r := range results {
		if r.OK {
			ok++
		} else {
			failed++
		}
	}
	if ok != 1 || failed != 2 {
		t.Fatalf("got %d ok, %d failed; want 1 and 2", ok, failed)
	}
	if _, err := os.Stat(filepath.Join(parent, "escape.txt")); !os.IsNotExist(err) {
		t.Fatal("entry escaped the output directory")
	}
	if got, err := os.ReadFile(filepath.Join(out, "safe", "ok.txt")); err != nil || string(got) != "payload" {
		t.Fatalf("safe entry: %q %v", got, err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(out, tempFilePattern))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left: %v", leftovers)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
