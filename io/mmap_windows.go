// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build windows

package io

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// mmappedFile is a read-only memory-mapped view of a file's contents, backed by a
// Windows file mapping object.
type mmappedFile struct {
	data      []byte
	mapHandle windows.Handle
}

// newMmappedFile maps f read-only for its first size bytes. mmap requires a non-zero
// length, so callers must not call this for empty files.
func newMmappedFile(f *os.File, size int64) (*mmappedFile, error) {
	mapHandle, err := windows.CreateFileMapping(
		windows.Handle(f.Fd()), nil, windows.PAGE_READONLY,
		uint32(size>>32), uint32(size&0xFFFFFFFF), nil,
	)
	if err != nil {
		return nil, fmt.Errorf("io/mmap: CreateFileMapping: %w", err)
	}

	addr, err := windows.MapViewOfFile(mapHandle, windows.FILE_MAP_READ, 0, 0, uintptr(size))
	if err != nil {
		windows.CloseHandle(mapHandle)
		return nil, fmt.Errorf("io/mmap: MapViewOfFile: %w", err)
	}

	data := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
	return &mmappedFile{data: data, mapHandle: mapHandle}, nil
}

func (m *mmappedFile) close() error {
	if m.data == nil {
		return nil
	}
	addr := uintptr(unsafe.Pointer(&m.data[0]))
	m.data = nil
	if err := windows.UnmapViewOfFile(addr); err != nil {
		windows.CloseHandle(m.mapHandle)
		return fmt.Errorf("io/mmap: UnmapViewOfFile: %w", err)
	}
	if err := windows.CloseHandle(m.mapHandle); err != nil {
		return fmt.Errorf("io/mmap: CloseHandle: %w", err)
	}
	return nil
}
