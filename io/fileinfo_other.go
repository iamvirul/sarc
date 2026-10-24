// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build !unix

package io

import (
	"io/fs"

	"github.com/iamvirul/sarc/archive"
)

// fileID identifies a file; hard links are not detected on this platform.
type fileID struct{}

func linkedFileID(fs.FileInfo) (fileID, bool) { return fileID{}, false }

// fileOwner returns nil: numeric ownership does not exist on this platform.
func fileOwner(fs.FileInfo) *archive.Owner { return nil }
