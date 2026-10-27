// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/iamvirul/sarc/archive"
)

func sampleDirectory() []archive.DirectoryRecord {
	return []archive.DirectoryRecord{
		{Offset: 120, Name: "data/a.txt", Attributes: archive.Attributes{Mode: 0o644, ModTime: 1_790_000_000_123_456_789,
			Xattrs: []archive.Xattr{{Name: "user.tag", Value: []byte("x")}}},
			SizeBucket: archive.BucketSmall, Codec: archive.CodecZstd, OriginalSize: 4000, StoredSize: 900},
		{Offset: 5000, Name: "data/s1", Attributes: archive.Attributes{Mode: 0o600, Owner: &archive.Owner{UID: 1, GID: 2}},
			SizeBucket: archive.BucketTiny, Codec: archive.CodecZstd, Solid: true, OriginalSize: 10, StoredSize: 3},
		{Offset: 5000, Name: "data/s2", Attributes: archive.Attributes{Mode: 0o600},
			SizeBucket: archive.BucketTiny, Codec: archive.CodecZstd, Solid: true, OriginalSize: 0, StoredSize: 0},
		{Offset: 9000, Name: "data", Attributes: archive.Attributes{Kind: archive.KindDirectory, Mode: 0o755}},
		{Offset: 9100, Name: "data/link", Attributes: archive.Attributes{Kind: archive.KindSymlink, Mode: 0o777, LinkTarget: "a.txt"}},
	}
}

func marshalDirectory(t *testing.T, records []archive.DirectoryRecord) []byte {
	t.Helper()
	b := archive.NewDirectory()
	for _, r := range records {
		var err error
		if b, err = archive.AppendDirectoryRecord(b, r); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

func TestDirectoryRoundtrip(t *testing.T) {
	want := sampleDirectory()
	got, err := archive.ParseDirectory(marshalDirectory(t, want))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("roundtrip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestEmptyDirectoryRoundtrip(t *testing.T) {
	got, err := archive.ParseDirectory(archive.NewDirectory())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d records, want 0", len(got))
	}
}

func TestAppendDirectoryRecordRejectsInvalidRecords(t *testing.T) {
	cases := map[string]archive.DirectoryRecord{
		"unsafe name":         {Name: "../escape"},
		"directory with data": {Name: "d", Attributes: archive.Attributes{Kind: archive.KindDirectory}, OriginalSize: 1},
	}
	for name, r := range cases {
		if _, err := archive.AppendDirectoryRecord(archive.NewDirectory(), r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseDirectoryRejectsMalformed(t *testing.T) {
	valid := marshalDirectory(t, sampleDirectory()[:1])
	// The first record is magic, offset (one varint byte), name length and name, then
	// flags, bucket, and codec.
	fieldsAt := len("SARCDIR1") + 1 + 1 + len("data/a.txt")
	withByte := func(i int, v byte) []byte {
		b := bytes.Clone(valid)
		b[i] = v
		return b
	}
	cases := map[string][]byte{
		"bad magic":      append([]byte("SARCDIR0"), valid[8:]...),
		"truncated":      valid[:len(valid)-1],
		"unknown flags":  withByte(fieldsAt, 0x80),
		"unknown bucket": withByte(fieldsAt+1, 0x09),
		"unknown codec":  withByte(fieldsAt+2, 0x09),
		"unsafe name":    bytes.Replace(valid, []byte("data/a.txt"), []byte("../a.txtxx"), 1),
		"too large":      append(archive.NewDirectory(), make([]byte, archive.MaxDirectorySize)...),
	}
	for name, b := range cases {
		if _, err := archive.ParseDirectory(b); !errors.Is(err, archive.ErrMalformedDirectory) {
			t.Errorf("%s: err = %v, want ErrMalformedDirectory", name, err)
		}
	}
}

func TestDirectoryLocatorRoundtrip(t *testing.T) {
	b := archive.AppendDirectoryLocator(nil, 1<<40+7)
	if len(b) != archive.DirectoryLocatorSize {
		t.Fatalf("locator is %d bytes, want %d", len(b), archive.DirectoryLocatorSize)
	}
	got, err := archive.ParseDirectoryLocator(b)
	if err != nil || got != 1<<40+7 {
		t.Fatalf("got %d, %v", got, err)
	}
	for i := range b[:1+len("SARCDLC1")] {
		bad := bytes.Clone(b)
		bad[i] ^= 0xff
		if _, err := archive.ParseDirectoryLocator(bad); !errors.Is(err, archive.ErrMalformedDirectory) {
			t.Errorf("corrupt byte %d: err = %v", i, err)
		}
	}
	if _, err := archive.ParseDirectoryLocator(b[1:]); err == nil {
		t.Error("short locator accepted")
	}
}
