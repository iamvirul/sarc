// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

// Package storagetest checks that a storage.Backend meets the contract the archive
// code relies on. Backend packages run it from their tests.
package storagetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/iamvirul/sarc/storage"
)

// Options tunes Run for a backend.
type Options struct {
	// LargeSize is the size of the object written to exercise multipart or chunked
	// uploads; it should exceed the backend's part size.
	LargeSize int
	// Versioned is set when Object reads detect replacement (ErrObjectChanged).
	Versioned bool
}

// Run tests b against the storage contract, writing objects under prefix.
func Run(t *testing.T, b storage.Backend, prefix string, opts Options) {
	ctx := context.Background()
	t.Run("CommitOnClose", func(t *testing.T) {
		key := prefix + "commit.sarc"
		w := mustCreate(t, b, key)
		write(t, w, []byte("archive"))
		if _, err := b.Open(ctx, key); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("object visible before Close: err = %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := w.Abort(); err != nil {
			t.Fatal("Abort after Close:", err)
		}
		requireContent(t, b, key, []byte("archive"))
	})
	t.Run("AbortLeavesNothing", func(t *testing.T) {
		key := prefix + "abort.sarc"
		w := mustCreate(t, b, key)
		write(t, w, randomBytes(t, opts.LargeSize))
		if err := w.Abort(); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal("Close after Abort:", err)
		}
		if _, err := b.Open(ctx, key); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("aborted object exists: err = %v", err)
		}
	})
	t.Run("LargeObjectRoundtrip", func(t *testing.T) {
		key := prefix + "large.sarc"
		data := randomBytes(t, opts.LargeSize)
		put(t, b, key, data)
		obj := requireContent(t, b, key, data)
		ra := storage.NewReaderAt(ctx, obj)
		for _, r := range [][2]int{{0, 1}, {len(data) - 1, 1}, {len(data) / 3, len(data) / 3}, {12345, 70000}} {
			got := make([]byte, r[1])
			if _, err := ra.ReadAt(got, int64(r[0])); err != nil {
				t.Fatalf("ReadAt(%d, %d): %v", r[0], r[1], err)
			}
			if !bytes.Equal(got, data[r[0]:r[0]+r[1]]) {
				t.Fatalf("ReadAt(%d, %d) returned wrong bytes", r[0], r[1])
			}
		}
	})
	t.Run("EmptyObject", func(t *testing.T) {
		key := prefix + "empty.sarc"
		put(t, b, key, nil)
		requireContent(t, b, key, nil)
	})
	t.Run("Overwrite", func(t *testing.T) {
		key := prefix + "overwrite.sarc"
		put(t, b, key, []byte("first"))
		put(t, b, key, []byte("second version"))
		requireContent(t, b, key, []byte("second version"))
	})
	t.Run("NotFound", func(t *testing.T) {
		if _, err := b.Open(ctx, prefix+"missing.sarc"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
	if opts.Versioned {
		t.Run("ObjectChanged", func(t *testing.T) {
			key := prefix + "changed.sarc"
			put(t, b, key, []byte("first"))
			obj, err := b.Open(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			put(t, b, key, []byte("replaced"))
			if _, err := io.ReadAll(storage.NewReader(ctx, obj)); !errors.Is(err, storage.ErrObjectChanged) {
				t.Fatalf("err = %v, want ErrObjectChanged", err)
			}
		})
	}
}

func mustCreate(t *testing.T, b storage.Backend, key string) storage.Writer {
	t.Helper()
	w, err := b.Create(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// write writes data in uneven pieces, as the archive writer's buffer does.
func write(t *testing.T, w storage.Writer, data []byte) {
	t.Helper()
	for len(data) > 0 {
		n := min(len(data), 1<<20+7)
		if _, err := w.Write(data[:n]); err != nil {
			t.Fatal(err)
		}
		data = data[n:]
	}
}

func put(t *testing.T, b storage.Backend, key string, data []byte) {
	t.Helper()
	w := mustCreate(t, b, key)
	write(t, w, data)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func requireContent(t *testing.T, b storage.Backend, key string, want []byte) storage.Object {
	t.Helper()
	obj, err := b.Open(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size() != int64(len(want)) {
		t.Fatalf("size %d, want %d", obj.Size(), len(want))
	}
	got, err := io.ReadAll(storage.NewReader(context.Background(), obj))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(want))
	}
	return obj
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
