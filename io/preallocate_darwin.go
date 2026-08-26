// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build darwin

package io

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// platformPreallocate reserves size bytes for f via fcntl(F_PREALLOCATE). Like Linux's
// FALLOC_FL_KEEP_SIZE, this reserves blocks without changing the file's reported size
// (stat st_size): the reservation is purely a block-layout hint, so no truncation is
// needed afterward and no zero-padding is ever visible to readers of the file while
// it's being written.
//
// Tries a contiguous allocation first (best for sequential write throughput); if the
// filesystem can't satisfy that, falls back to a non-contiguous reservation, which
// still avoids the extend-on-every-write pattern this optimisation targets.
func platformPreallocate(f *os.File, size int64) error {
	fstore := unix.Fstore_t{
		Flags:   unix.F_ALLOCATECONTIG,
		Posmode: unix.F_PEOFPOSMODE,
		Offset:  0,
		Length:  size,
	}
	if err := unix.FcntlFstore(f.Fd(), unix.F_PREALLOCATE, &fstore); err != nil {
		fstore.Flags = unix.F_ALLOCATEALL
		if err := unix.FcntlFstore(f.Fd(), unix.F_PREALLOCATE, &fstore); err != nil {
			return fmt.Errorf("io/preallocate: fcntl F_PREALLOCATE: %w", err)
		}
	}
	return nil
}
