// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

// Package local is the storage backend for file:///path locations, using only the
// standard library.
package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/iamvirul/sarc/storage"
)

// Backend stores objects as files; keys are absolute slash-separated paths without
// their leading slash.
type Backend struct{}

// New returns the backend for file:// locations, whose host must be empty or localhost.
func New(_ context.Context, host string) (storage.Backend, error) {
	if host != "" && host != "localhost" {
		return nil, fmt.Errorf("file:// locations cannot name a remote host; use file:///path")
	}
	return Backend{}, nil
}

// path returns the file path of key.
func path(key string) string {
	p := filepath.FromSlash(key)
	if runtime.GOOS == "windows" && filepath.VolumeName(p) != "" {
		return p
	}
	return string(filepath.Separator) + p
}

// Create writes to a hidden temporary file beside the target, renamed into place on
// Close, so an aborted or failed write never leaves a partial archive under the name.
func (Backend) Create(_ context.Context, key string) (storage.Writer, error) {
	target := path(key)
	f, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".*.partial")
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", target, err)
	}
	return &writer{f: f, target: target}, nil
}

type writer struct {
	f      *os.File
	target string
	done   bool
}

func (w *writer) Write(p []byte) (int, error) { return w.f.Write(p) }

func (w *writer) Close() error {
	if w.done {
		return nil
	}
	w.done = true
	err := w.f.Sync()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(w.f.Name(), w.target)
	}
	if err != nil {
		os.Remove(w.f.Name())
		return fmt.Errorf("commit %s: %w", w.target, err)
	}
	return nil
}

func (w *writer) Abort() error {
	if w.done {
		return nil
	}
	w.done = true
	w.f.Close()
	return os.Remove(w.f.Name())
}

// Open returns the file at key. Local files carry no version, so a file replaced after
// Open is read as it is at each read.
func (Backend) Open(_ context.Context, key string) (storage.Object, error) {
	p := path(key)
	info, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("open %s: %w", p, storage.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", p, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("open %s: not a regular file", p)
	}
	return object{path: p, size: info.Size()}, nil
}

type object struct {
	path string
	size int64
}

func (o object) Size() int64 { return o.size }

func (o object) NewRangeReader(_ context.Context, offset, length int64) (io.ReadCloser, error) {
	f, err := os.Open(o.path)
	if err != nil {
		return nil, err
	}
	if length < 0 {
		length = o.size - offset
	}
	return struct {
		io.Reader
		io.Closer
	}{io.NewSectionReader(f, offset, length), f}, nil
}
