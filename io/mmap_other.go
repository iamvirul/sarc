// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build !unix && !windows

package io

import (
	"errors"
	"os"
)

// mmappedFile is unused on platforms without an mmap implementation; newMmappedFile
// always fails here so callers fall back to the buffered reader path. data is kept
// only so this type's shape matches the unix/windows variants for callers that
// reference it unconditionally.
type mmappedFile struct {
	data []byte
}

var errMmapUnsupported = errors.New("io/mmap: not supported on this platform")

func newMmappedFile(f *os.File, size int64) (*mmappedFile, error) {
	return nil, errMmapUnsupported
}

func (m *mmappedFile) close() error {
	return nil
}
