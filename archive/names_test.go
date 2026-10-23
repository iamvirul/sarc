// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive_test

import (
	"strings"
	"testing"

	"github.com/iamvirul/sarc/archive"
)

func TestValidEntryName(t *testing.T) {
	valid := []string{
		"a", "main.go", ".hidden", "with space.txt", "docs/report.pdf", "a/b/c/d.txt", "dir/.hidden/x",
		"..dots", "file..", strings.Repeat("x", archive.MaxEntryNameLen),
	}
	invalid := []string{
		"", ".", "..", "/etc/passwd", "../escape", "a/../../b", "a/./b", "a//b", "dir/", "a/..",
		`back\slash`, `..\escape`, "nul\x00byte", strings.Repeat("x", archive.MaxEntryNameLen+1),
	}
	for _, name := range valid {
		if !archive.ValidEntryName(name) {
			t.Errorf("%q rejected", name)
		}
	}
	for _, name := range invalid {
		if archive.ValidEntryName(name) {
			t.Errorf("%q accepted", name)
		}
	}
}
