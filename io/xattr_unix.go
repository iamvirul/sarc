// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build linux || darwin

package io

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"

	"golang.org/x/sys/unix"

	"github.com/iamvirul/sarc/archive"
)

// xattrRetries bounds re-reads when attributes change size while being listed.
const xattrRetries = 4

// readXattrs returns the extended attributes of path, without following a final
// symlink, sorted by name. A filesystem without extended attributes yields none.
func readXattrs(path string) ([]archive.Xattr, error) {
	names, err := listXattrs(path)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	xattrs := make([]archive.Xattr, 0, len(names))
	for _, name := range names {
		value, err := getXattr(path, name)
		if errors.Is(err, xattrMissing) {
			continue // removed while reading
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		xattrs = append(xattrs, archive.Xattr{Name: name, Value: value})
		if archive.XattrsSize(xattrs) > archive.MaxXattrsSize {
			return xattrs, nil // the caller rejects the set as too large
		}
	}
	return xattrs, nil
}

func listXattrs(path string) ([]string, error) {
	for range xattrRetries {
		size, err := unix.Llistxattr(path, nil)
		if unsupportedXattrs(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if size == 0 {
			return nil, nil
		}
		buf := make([]byte, size)
		n, err := unix.Llistxattr(path, buf)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var names []string
		for _, name := range bytes.Split(buf[:n], []byte{0}) {
			if len(name) > 0 && len(name) <= archive.MaxXattrNameLen {
				names = append(names, string(name))
			}
		}
		sort.Strings(names)
		return names, nil
	}
	return nil, errors.New("extended attributes kept changing while listed")
}

func getXattr(path, name string) ([]byte, error) {
	for range xattrRetries {
		size, err := unix.Lgetxattr(path, name, nil)
		if err != nil {
			return nil, classifyXattrErr(err)
		}
		if size > archive.MaxXattrsSize {
			return make([]byte, archive.MaxXattrsSize+1), nil
		}
		buf := make([]byte, size)
		n, err := unix.Lgetxattr(path, name, buf)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if err != nil {
			return nil, classifyXattrErr(err)
		}
		return buf[:n], nil
	}
	return nil, errors.New("extended attribute kept changing while read")
}

// xattrMissing marks an attribute that disappeared between listing and reading it.
var xattrMissing = errors.New("extended attribute missing")

func classifyXattrErr(err error) error {
	if errors.Is(err, unix.ENODATA) || errors.Is(err, errNoXattr) {
		return xattrMissing
	}
	return err
}

func unsupportedXattrs(err error) bool {
	return errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP)
}

// writeXattrs sets xattrs on the open file f and returns how many could not be set,
// with the first failure. Some namespaces (Linux security.* and trusted.*) need
// privileges, so failures are reported rather than fatal.
func writeXattrs(f *os.File, xattrs []archive.Xattr) (int, error) {
	failed := 0
	var first error
	for _, x := range xattrs {
		if err := unix.Fsetxattr(int(f.Fd()), x.Name, x.Value, 0); err != nil {
			failed++
			if first == nil {
				first = fmt.Errorf("%s: %w", x.Name, err)
			}
		}
	}
	return failed, first
}
