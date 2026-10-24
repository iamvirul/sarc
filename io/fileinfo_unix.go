// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build unix

package io

import (
	"io/fs"
	"syscall"

	"github.com/iamvirul/sarc/archive"
)

// fileID identifies a file by device and inode.
type fileID struct{ dev, ino uint64 }

// linkedFileID returns the identity of a file with more than one hard link.
func linkedFileID(info fs.FileInfo) (fileID, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink < 2 {
		return fileID{}, false
	}
	return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
}

// fileOwner returns the numeric owner of info.
func fileOwner(info fs.FileInfo) *archive.Owner {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return &archive.Owner{UID: st.Uid, GID: st.Gid}
}
