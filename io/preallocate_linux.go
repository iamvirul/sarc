// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build linux

package io

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// platformPreallocate reserves size bytes for f via fallocate(2). FALLOC_FL_KEEP_SIZE
// keeps the file's reported size (stat st_size) unchanged: the reservation is purely a
// block-layout hint, so no truncation is needed afterward and no zero-padding is ever
// visible to readers of the file while it's being written.
func platformPreallocate(f *os.File, size int64) error {
	if err := unix.Fallocate(int(f.Fd()), unix.FALLOC_FL_KEEP_SIZE, 0, size); err != nil {
		return fmt.Errorf("io/preallocate: fallocate: %w", err)
	}
	return nil
}
