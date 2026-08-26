// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"errors"
	"os"
)

// preallocateOverhead is applied to the sum of input file sizes to estimate the final
// archive size: per-file frame header, metadata, padding, and trailer overhead, plus
// the AES-GCM tag on every ~256 KB block, together run a few percent over the raw
// input size. 12% comfortably covers that without over-reserving disk space.
const preallocateOverhead = 1.12

// estimateArchiveSize returns the predicted final archive size for totalInputBytes,
// used to pre-reserve disk space before writing.
func estimateArchiveSize(totalInputBytes int64) int64 {
	return int64(float64(totalInputBytes) * preallocateOverhead)
}

// preallocate reserves size bytes of disk space for f without changing its logical
// end-of-file (later sequential Write calls still advance the file's reported size
// exactly as they would without preallocation), so the OS can lay out those blocks
// contiguously instead of extending the file one allocation at a time as data streams
// in. This is a best-effort optimisation: any error (size <= 0, unsupported filesystem,
// unsupported platform) is returned for the caller to log and ignore, never to fail the
// archive operation, since preallocation has no effect on wire format or correctness.
func preallocate(f *os.File, size int64) error {
	if size <= 0 {
		return errors.New("io/preallocate: size must be positive")
	}
	return platformPreallocate(f, size)
}

// PreallocateOutput estimates the final archive size from totalInputBytes and reserves
// that much disk space for f before any archive data is written, so the filesystem can
// lay out blocks contiguously instead of extending the file on every write. Best-effort:
// callers should log a returned error and continue archiving rather than treat it as
// fatal, since this has no effect on wire format or correctness, only write throughput.
func PreallocateOutput(f *os.File, totalInputBytes int64) error {
	return preallocate(f, estimateArchiveSize(totalInputBytes))
}
