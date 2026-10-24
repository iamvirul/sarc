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
	files, skipped := expandInputs([]string{filepath.Join(root, "data") + string(filepath.Separator), filepath.Join(root, "loose.txt")}, walkOptions{})
	if len(skipped) != 0 {
		t.Fatalf("unexpected skips: %+v", skipped)
	}
	want := []string{"data", "data/.hidden", "data/a.txt", "data/b.txt", "data/sub", "data/sub/deep", "data/sub/deep/c.txt", "loose.txt"}
	if got := storedNames(files); !equalStrings(got, want) {
		t.Fatalf("stored names %q, want %q", got, want)
	}
}

func TestExpandInputsDotDirectoryHasNoPrefix(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"a.txt": "a", "sub/b.txt": "b"})
	t.Chdir(root)
	files, _ := expandInputs([]string{"."}, walkOptions{})
	if got, want := storedNames(files), []string{"a.txt", "sub", "sub/b.txt"}; !equalStrings(got, want) {
		t.Fatalf("stored names %q, want %q", got, want)
	}
}

func TestExpandInputsRecordsKindsAndLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks and hard links need privileges on Windows")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{"data/real.txt": "r", "data/sub/x.txt": "x"})
	data := filepath.Join(root, "data")
	if err := os.Symlink("real.txt", filepath.Join(data, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(data, "real.txt"), filepath.Join(data, "zhard.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(data, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	files, skipped := expandInputs([]string{data}, walkOptions{owner: true})
	if len(skipped) != 0 {
		t.Fatalf("unexpected skips: %+v", skipped)
	}
	kinds := map[string]archive.Attributes{}
	for _, f := range files {
		kinds[f.name] = f.attrs
	}
	want := map[string]archive.FileKind{
		"data": archive.KindDirectory, "data/link.txt": archive.KindSymlink, "data/real.txt": archive.KindRegular,
		"data/sub": archive.KindDirectory, "data/sub/x.txt": archive.KindRegular, "data/zhard.txt": archive.KindHardlink,
	}
	if len(kinds) != len(want) {
		t.Fatalf("entries %v", storedNames(files))
	}
	for name, kind := range want {
		if kinds[name].Kind != kind {
			t.Fatalf("%s: kind %v, want %v", name, kinds[name].Kind, kind)
		}
	}
	if kinds["data/link.txt"].LinkTarget != "real.txt" || kinds["data/zhard.txt"].LinkTarget != "data/real.txt" {
		t.Fatalf("link targets %q %q", kinds["data/link.txt"].LinkTarget, kinds["data/zhard.txt"].LinkTarget)
	}
	if kinds["data/sub"].Mode != 0o750 || kinds["data/real.txt"].ModTime == 0 || kinds["data/real.txt"].Owner == nil {
		t.Fatalf("attributes not recorded: %+v %+v", kinds["data/sub"], kinds["data/real.txt"])
	}
}

func TestExpandInputsReportsMissingArguments(t *testing.T) {
	files, skipped := expandInputs([]string{filepath.Join(t.TempDir(), "missing")}, walkOptions{})
	var ae *ArchiveError
	if len(files) != 0 || len(skipped) != 1 || !errors.As(skipped[0].err, &ae) || ae.IsFatal() {
		t.Fatalf("want one recoverable skip, got files %v skipped %+v", files, skipped)
	}
}

func TestLocalNameRefusesEscapes(t *testing.T) {
	for _, name := range []string{"../escape.txt", "/etc/passwd", "a/../../b", `..\b`, "", "dir/"} {
		if _, err := localName(name); err == nil {
			t.Fatalf("%q accepted", name)
		}
	}
	got, err := localName("docs/2026/report.pdf")
	if err != nil || got != filepath.Join("docs", "2026", "report.pdf") {
		t.Fatalf("localName: %q %v", got, err)
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
		entry, _, err := encryptFile(inputFile{path: src, name: name, attrs: archive.Attributes{Mode: 0o644}}, aw, policy, NopProgressTracker{})
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
