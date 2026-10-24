// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build linux || darwin

package tests_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/iamvirul/sarc/archive"
	sarcio "github.com/iamvirul/sarc/io"
)

const metadataTestPassword = "metadata-test-pass"

var fixedTime = time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)

// metadataTree builds a tree with every kind of entry and attribute, and returns
// whether user extended attributes are supported here.
func metadataTree(t *testing.T, root string) bool {
	t.Helper()
	data := filepath.Join(root, "data")
	for _, d := range []string{"bin", "empty", "locked", "sub"} {
		if err := os.MkdirAll(filepath.Join(data, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]os.FileMode{"bin/run.sh": 0o755, "secret.txt": 0o600, "sub/readme.md": 0o644, "locked/inner.txt": 0o444}
	for name, mode := range files {
		p := filepath.Join(data, name)
		if err := os.WriteFile(p, []byte("content of "+name), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Symlink("../secret.txt", filepath.Join(data, "bin", "relative-link")))
	must(os.Symlink("/nonexistent/absolute/target", filepath.Join(data, "dangling")))
	must(os.Link(filepath.Join(data, "secret.txt"), filepath.Join(data, "sub", "hardlink.txt")))
	xattrs := unix.Setxattr(filepath.Join(data, "sub", "readme.md"), "user.sarc.test", []byte("xattr value"), 0) == nil
	if xattrs {
		must(unix.Setxattr(filepath.Join(data, "empty"), "user.sarc.dir", []byte("on a directory"), 0))
	}
	for _, p := range []string{"secret.txt", "sub/readme.md", "empty", "sub"} {
		must(os.Chtimes(filepath.Join(data, p), fixedTime, fixedTime))
	}
	must(os.Chmod(filepath.Join(data, "locked"), 0o555))
	must(os.Chmod(filepath.Join(data, "sub"), 0o750))
	t.Cleanup(func() { os.Chmod(filepath.Join(data, "locked"), 0o755) })
	return xattrs
}

// requireMetadataRestored checks out/data matches the tree metadataTree built.
func requireMetadataRestored(t *testing.T, out string, xattrs bool) {
	t.Helper()
	data := filepath.Join(out, "data")
	t.Cleanup(func() { os.Chmod(filepath.Join(data, "locked"), 0o755) })
	modes := map[string]os.FileMode{
		"bin/run.sh": 0o755, "secret.txt": 0o600, "sub/readme.md": 0o644, "locked/inner.txt": 0o444,
		"locked": 0o555 | os.ModeDir, "sub": 0o750 | os.ModeDir, "empty": 0o755 | os.ModeDir,
	}
	for name, want := range modes {
		info, err := os.Lstat(filepath.Join(data, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := info.Mode() & (os.ModePerm | os.ModeDir); got != want {
			t.Errorf("%s: mode %v, want %v", name, got, want)
		}
	}
	for name, target := range map[string]string{"bin/relative-link": "../secret.txt", "dangling": "/nonexistent/absolute/target"} {
		got, err := os.Readlink(filepath.Join(data, name))
		if err != nil || got != target {
			t.Errorf("%s: link %q, %v; want %q", name, got, err, target)
		}
	}
	a, err := os.Stat(filepath.Join(data, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(filepath.Join(data, "sub", "hardlink.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(a, b) {
		t.Error("hard link restored as a separate file")
	}
	for _, p := range []string{"secret.txt", "sub/readme.md", "empty", "sub"} {
		info, err := os.Stat(filepath.Join(data, p))
		if err != nil || !info.ModTime().Equal(fixedTime) {
			t.Errorf("%s: modification time %v, want %v", p, info.ModTime(), fixedTime)
		}
	}
	if got, err := os.ReadFile(filepath.Join(data, "bin", "run.sh")); err != nil || string(got) != "content of bin/run.sh" {
		t.Errorf("content: %q %v", got, err)
	}
	if !xattrs {
		return
	}
	for p, want := range map[string]string{"sub/readme.md": "xattr value", "empty": "on a directory"} {
		name := map[string]string{"sub/readme.md": "user.sarc.test", "empty": "user.sarc.dir"}[p]
		buf := make([]byte, 64)
		n, err := unix.Getxattr(filepath.Join(data, p), name, buf)
		if err != nil || string(buf[:n]) != want {
			t.Errorf("%s: xattr %q, %v; want %q", p, buf[:max(n, 0)], err, want)
		}
	}
}

func TestMetadataRoundtripInEveryMode(t *testing.T) {
	root := t.TempDir()
	xattrs := metadataTree(t, root)
	if !xattrs {
		t.Log("user extended attributes unsupported on this filesystem; checking the rest")
	}
	dataDir := filepath.Join(root, "data")
	solid := sarcio.DefaultCompressionOptions()
	solid.Solid = true
	for name, build := range map[string]func(t *testing.T) string{
		"concurrent": func(t *testing.T) string {
			return archiveTo(t, func(buf *bytes.Buffer) error {
				ca, err := sarcio.NewConcurrentArchiver(buf, metadataTestPassword, 4, nil)
				if err != nil {
					return err
				}
				return ca.Archive([]string{dataDir})
			})
		},
		"solid": func(t *testing.T) string {
			return archiveTo(t, func(buf *bytes.Buffer) error {
				ca, err := sarcio.NewConcurrentArchiver(buf, metadataTestPassword, 4, nil, sarcio.WithCompression(solid))
				if err != nil {
					return err
				}
				return ca.Archive([]string{dataDir})
			})
		},
		"streaming": func(t *testing.T) string {
			return archiveTo(t, func(buf *bytes.Buffer) error {
				sa, err := sarcio.NewStreamingArchiver(buf, metadataTestPassword, nil)
				if err != nil {
					return err
				}
				if err := sa.AddFile(dataDir); err != nil {
					return err
				}
				return sa.Finalize(0, 0)
			})
		},
		"incremental": func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "inc.sarc")
			if _, err := sarcio.ArchiveIncremental(path, []string{dataDir}, sarcio.IncrementalOptions{Password: metadataTestPassword}); err != nil {
				t.Fatal(err)
			}
			return path
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := build(t)
			out := t.TempDir()
			results, err := openIncremental(t, path, metadataTestPassword).Extract(out)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range results {
				if !r.OK {
					t.Errorf("%s: %v", r.Filename, r.Err)
				}
			}
			requireMetadataRestored(t, out, xattrs)
		})
	}
}

// archiveTo writes an archive built by build to a file and returns its path.
func archiveTo(t *testing.T, build func(*bytes.Buffer) error) string {
	t.Helper()
	var buf bytes.Buffer
	if err := build(&buf); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "a.sarc")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// warnings collects Warner notices.
type warnings struct {
	sarcio.NopProgressTracker
	messages []string
}

func (w *warnings) Warn(name, message string) { w.messages = append(w.messages, message) }

func TestOwnershipIsRecordedOnlyWhenAskedAndRestoredOnlyWhenAsked(t *testing.T) {
	src := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(src, "tool"), 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	extract := func(path string, restore bool) (string, []string) {
		t.Helper()
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		w := &warnings{}
		out := t.TempDir()
		ex := sarcio.NewSafeExtractor(f, metadataTestPassword, w, sarcio.WithRestoreOwner(restore))
		if _, err := ex.Extract(out); err != nil {
			t.Fatal(err)
		}
		return out, w.messages
	}
	build := func(opts ...sarcio.ArchiverOption) string {
		return archiveTo(t, func(buf *bytes.Buffer) error {
			ca, err := sarcio.NewConcurrentArchiver(buf, metadataTestPassword, 2, nil, opts...)
			if err != nil {
				return err
			}
			return ca.Archive([]string{src})
		})
	}

	plain := build()
	out, messages := extract(plain, false)
	if !hasMessage(messages, "setuid") || hasMessage(messages, "ownership") {
		t.Fatalf("without owners: %q", messages)
	}
	if info, _ := os.Stat(filepath.Join(out, "data", "tool")); info.Mode()&os.ModeSetuid != 0 {
		t.Fatal("setuid restored without --preserve-owner")
	}

	owned := build(sarcio.WithPreserveOwner(true))
	if _, messages := extract(owned, false); !hasMessage(messages, "ownership recorded in the archive was not restored") {
		t.Fatalf("owners skipped silently: %q", messages)
	}
	out, messages = extract(owned, true)
	info, err := os.Stat(filepath.Join(out, "data", "tool"))
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 || int(info.Sys().(*syscall.Stat_t).Uid) == os.Geteuid() {
		// Restoring one's own owner needs no privilege, so setuid comes back too.
		if info.Mode()&os.ModeSetuid == 0 || len(messages) != 0 {
			t.Fatalf("restored owner: mode %v, warnings %q", info.Mode(), messages)
		}
	}
}

func hasMessage(messages []string, part string) bool {
	for _, m := range messages {
		if strings.Contains(m, part) {
			return true
		}
	}
	return false
}

// TestIncrementalDetectsMetadataChanges retargets a symlink and changes an extended
// attribute and a mode without touching contents: each is recorded as a change.
func TestIncrementalDetectsMetadataChanges(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(data, "a.txt")
	if err := os.WriteFile(file, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(data, "link")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "inc.sarc")
	run := func() sarcio.IncrementalResult {
		t.Helper()
		res, err := sarcio.ArchiveIncremental(path, []string{data}, sarcio.IncrementalOptions{
			Password: metadataTestPassword, UnlockPassword: metadataTestPassword,
		})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	run()
	if res := run(); res.Changed != 0 {
		t.Fatalf("unchanged run: %+v", res)
	}
	keepDirTime := func() {
		t.Helper()
		if err := os.Chtimes(data, fixedTime, fixedTime); err != nil {
			t.Fatal(err)
		}
	}
	keepDirTime()
	run()

	if err := os.Remove(filepath.Join(data, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(data, "link")); err != nil {
		t.Fatal(err)
	}
	keepDirTime()
	if res := run(); res.Changed != 1 || res.NewChunks != 0 {
		t.Fatalf("retargeted symlink: %+v", res)
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	if res := run(); res.Changed != 1 || res.NewChunks != 0 {
		t.Fatalf("mode change: %+v", res)
	}
	if err := unix.Setxattr(file, "user.sarc.changed", []byte("v"), 0); err == nil {
		if res := run(); res.Changed != 1 || res.NewChunks != 0 {
			t.Fatalf("xattr change: %+v", res)
		}
	} else if !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EOPNOTSUPP) {
		t.Fatal(err)
	}

	list, err := openIncremental(t, path, metadataTestPassword).List()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range list {
		if r.Filename == "data/link" && (r.Kind != archive.KindSymlink || r.LinkTarget != "elsewhere") {
			t.Fatalf("listed link %+v", r)
		}
		if r.Filename == "data/a.txt" && r.Mode != 0o600 {
			t.Fatalf("listed mode %o", r.Mode)
		}
	}
}
