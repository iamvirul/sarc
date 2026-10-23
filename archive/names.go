// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import "strings"

// MaxEntryNameLen bounds a stored file name in bytes.
const MaxEntryNameLen = 0xFFFF

// ValidEntryName reports whether name is a safe stored file name: a relative,
// slash-separated path such as "docs/report.pdf" whose elements are non-empty and not
// "." or "..", with no NUL or backslash, of at most MaxEntryNameLen bytes. Readers
// refuse other names, so an archive cannot write outside the extraction directory.
func ValidEntryName(name string) bool {
	if name == "" || len(name) > MaxEntryNameLen || strings.ContainsAny(name, "\x00\\") {
		return false
	}
	for _, elem := range strings.Split(name, "/") {
		if elem == "" || elem == "." || elem == ".." {
			return false
		}
	}
	return true
}
