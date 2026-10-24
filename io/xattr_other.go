// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build !linux && !darwin

package io

import (
	"errors"
	"os"

	"github.com/iamvirul/sarc/archive"
)

// readXattrs returns no attributes: this platform's extended attributes are not
// supported.
func readXattrs(string) ([]archive.Xattr, error) { return nil, nil }

// writeXattrs cannot set extended attributes on this platform.
func writeXattrs(_ *os.File, xattrs []archive.Xattr) (int, error) {
	if len(xattrs) == 0 {
		return 0, nil
	}
	return len(xattrs), errors.New("extended attributes are not supported on this platform")
}
