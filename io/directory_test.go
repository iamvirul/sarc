// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/iamvirul/sarc/archive"
)

func TestDirectoryBuilderStopsAtMaxSize(t *testing.T) {
	d := newDirectoryBuilder()
	name := strings.Repeat("n", 4000)
	for i := 0; !d.full; i++ {
		if i > archive.MaxDirectorySize/len(name)+1 {
			t.Fatal("directory never filled")
		}
		if err := d.add(archive.DirectoryRecord{Name: name, Attributes: archive.Attributes{Mode: 0o644}}); err != nil {
			t.Fatal(err)
		}
	}
	aw := newTestArchiveWriter(t)
	before := aw.Offset()
	if err := d.write(aw); err != nil {
		t.Fatal(err)
	}
	if aw.Offset() != before {
		t.Fatal("full directory builder wrote a directory")
	}
}

func TestDirectoryBuilderRejectsInvalidRecord(t *testing.T) {
	if err := newDirectoryBuilder().add(archive.DirectoryRecord{Name: "../x"}); err == nil || !isFatal(err) {
		t.Fatalf("err = %v, want fatal", err)
	}
}

func TestArchiveWithoutDirectoryListsByScanning(t *testing.T) {
	dir := t.TempDir()
	paths := []string{writeSizedFile(t, dir, "a.bin", 300<<10), writeSizedFile(t, dir, "b.txt", 10)}
	var buf bytes.Buffer
	ca, err := NewConcurrentArchiver(&buf, "no-directory-test", 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	ca.dir.full = true // as when the directory outgrows archive.MaxDirectorySize
	if err := ca.Archive(paths); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()

	scanned, err := NewSafeExtractor(bytes.NewReader(data), "no-directory-test", nil).List()
	if err != nil {
		t.Fatal(err)
	}
	random, err := NewSafeExtractor(bytes.NewReader(data), "no-directory-test", nil,
		WithRandomAccess(bytes.NewReader(data), int64(len(data)))).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(scanned) != 2 || !reflect.DeepEqual(random, scanned) {
		t.Fatalf("random-access listing %+v differs from scan %+v", random, scanned)
	}
}
