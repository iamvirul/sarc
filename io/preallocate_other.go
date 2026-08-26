// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build !linux && !darwin

package io

import (
	"errors"
	"os"
)

// platformPreallocate has no implementation on this platform (no portable equivalent
// of fallocate/F_PREALLOCATE that reserves space without changing the file's reported
// size), so callers fall back to ordinary sequential writes.
func platformPreallocate(f *os.File, size int64) error {
	return errors.New("io/preallocate: not supported on this platform")
}
