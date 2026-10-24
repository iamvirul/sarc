// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"testing"

	"github.com/iamvirul/sarc/archive"
	sarcio "github.com/iamvirul/sarc/io"
)

func TestFormatMode(t *testing.T) {
	for _, c := range []struct {
		kind archive.FileKind
		mode uint32
		want string
	}{
		{archive.KindRegular, 0o644, "-rw-r--r--"},
		{archive.KindRegular, 0o4755, "-rwsr-xr-x"},
		{archive.KindRegular, 0o4644, "-rwSr--r--"},
		{archive.KindDirectory, 0o2750, "drwxr-s---"},
		{archive.KindDirectory, 0o1777, "drwxrwxrwt"},
		{archive.KindDirectory, 0o1770, "drwxrwx--T"},
		{archive.KindSymlink, 0o777, "lrwxrwxrwx"},
		{archive.KindHardlink, 0o600, "-rw-------"},
	} {
		if got := formatMode(c.kind, c.mode); got != c.want {
			t.Errorf("formatMode(%v, %o) = %s, want %s", c.kind, c.mode, got, c.want)
		}
	}
}

func TestFormatName(t *testing.T) {
	for _, c := range []struct {
		r    sarcio.ListResult
		want string
	}{
		{sarcio.ListResult{Filename: "a.txt"}, "a.txt"},
		{sarcio.ListResult{Filename: "bin/link", Kind: archive.KindSymlink, LinkTarget: "../a.txt"}, "bin/link -> ../a.txt"},
		{sarcio.ListResult{Filename: "copy", Kind: archive.KindHardlink, LinkTarget: "a.txt"}, "copy => a.txt"},
	} {
		if got := formatName(c.r); got != c.want {
			t.Errorf("formatName = %q, want %q", got, c.want)
		}
	}
}
