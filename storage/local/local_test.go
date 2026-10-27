// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package local_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamvirul/sarc/storage"
	"github.com/iamvirul/sarc/storage/local"
	"github.com/iamvirul/sarc/storage/storagetest"
)

func backend(t *testing.T) storage.Backend {
	t.Helper()
	b, err := local.New(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// keyFor returns the file:// key of path.
func keyFor(t *testing.T, path string) string {
	t.Helper()
	loc, ok, err := storage.ParseLocation("file://" + filepath.ToSlash(withLeadingSlash(path)))
	if !ok || err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return loc.Key
}

func withLeadingSlash(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names
}

func TestCreateCommitsOnlyOnClose(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a.sarc")
	w, err := backend(t).Create(context.Background(), keyFor(t, target))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("archive bytes")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("target visible before Close")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "archive bytes" {
		t.Fatalf("got %q, %v", got, err)
	}
	if err := w.Abort(); err != nil {
		t.Fatal("Abort after Close should be a no-op:", err)
	}
	if names := dirEntries(t, dir); len(names) != 1 {
		t.Fatalf("leftover files: %v", names)
	}
}

func TestAbortLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	w, err := backend(t).Create(context.Background(), keyFor(t, filepath.Join(dir, "a.sarc")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}
	if names := dirEntries(t, dir); len(names) != 0 {
		t.Fatalf("aborted write left %v", names)
	}
}

func TestCreateInMissingDirectoryFails(t *testing.T) {
	_, err := backend(t).Create(context.Background(), keyFor(t, filepath.Join(t.TempDir(), "missing", "a.sarc")))
	if err == nil {
		t.Fatal("create in a missing directory succeeded")
	}
}

func TestOpenReadsRanges(t *testing.T) {
	target := filepath.Join(t.TempDir(), "a.sarc")
	if err := os.WriteFile(target, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	obj, err := backend(t).Open(context.Background(), keyFor(t, target))
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size() != 10 {
		t.Fatalf("size %d, want 10", obj.Size())
	}
	for _, c := range []struct {
		off, n int64
		want   string
	}{{0, -1, "0123456789"}, {3, 4, "3456"}, {7, -1, "789"}} {
		r, err := obj.NewRangeReader(context.Background(), c.off, c.n)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		r.Close()
		if err != nil || string(got) != c.want {
			t.Errorf("range(%d, %d) = %q, %v; want %q", c.off, c.n, got, err, c.want)
		}
	}
}

func TestOpenMissingAndNonRegular(t *testing.T) {
	dir := t.TempDir()
	if _, err := backend(t).Open(context.Background(), keyFor(t, filepath.Join(dir, "nope"))); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("missing file: err = %v, want ErrNotFound", err)
	}
	if _, err := backend(t).Open(context.Background(), keyFor(t, dir)); err == nil {
		t.Error("opening a directory succeeded")
	}
}

func TestNewRejectsRemoteHost(t *testing.T) {
	if _, err := local.New(context.Background(), "server"); err == nil {
		t.Fatal("remote host accepted")
	}
	if _, err := local.New(context.Background(), "localhost"); err != nil {
		t.Fatal(err)
	}
}

func TestContract(t *testing.T) {
	storagetest.Run(t, backend(t), keyFor(t, t.TempDir())+"/", storagetest.Options{LargeSize: 3 << 20})
}
