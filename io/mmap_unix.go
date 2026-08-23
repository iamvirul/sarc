// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build unix

package io

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// mmappedFile is a read-only memory-mapped view of a file's contents. Reading through
// data touches OS-managed page-cache pages directly instead of copying through a
// userspace read() buffer.
type mmappedFile struct {
	data []byte
}

// newMmappedFile maps f read-only for its first size bytes. mmap requires a non-zero
// length, so callers must not call this for empty files.
func newMmappedFile(f *os.File, size int64) (*mmappedFile, error) {
	data, err := unix.Mmap(int(f.Fd()), 0, int(size), unix.PROT_READ, unix.MAP_SHARED|mmapPopulateFlag)
	if err != nil {
		return nil, fmt.Errorf("io/mmap: mmap: %w", err)
	}
	return &mmappedFile{data: data}, nil
}

func (m *mmappedFile) close() error {
	if m.data == nil {
		return nil
	}
	err := unix.Munmap(m.data)
	m.data = nil
	if err != nil {
		return fmt.Errorf("io/mmap: munmap: %w", err)
	}
	return nil
}
