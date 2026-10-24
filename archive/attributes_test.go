// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive_test

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/iamvirul/sarc/archive"
)

func TestAttributesRoundtrip(t *testing.T) {
	for _, want := range []archive.Attributes{
		{Kind: archive.KindRegular, Mode: 0o644, ModTime: 1_790_000_000_123_456_789},
		{Kind: archive.KindRegular, Mode: 0o4755, Owner: &archive.Owner{UID: 0, GID: 0}},
		{Kind: archive.KindDirectory, Mode: 0o1777, ModTime: -1},
		{Kind: archive.KindSymlink, Mode: 0o777, LinkTarget: "../shared/lib.so.1"},
		{Kind: archive.KindHardlink, Mode: 0o644, LinkTarget: "data/original.bin"},
		{Kind: archive.KindRegular, Mode: 0o600, Xattrs: []archive.Xattr{
			{Name: "user.comment", Value: []byte("hello")},
			{Name: "system.posix_acl_access", Value: []byte{2, 0, 0, 0, 1, 0, 6, 0}},
			{Name: "com.apple.ResourceFork", Value: bytes.Repeat([]byte{7}, 70_000)},
			{Name: "user.empty", Value: []byte{}},
		}},
	} {
		b, err := archive.AppendAttributes(nil, want)
		if err != nil {
			t.Fatal(err)
		}
		got, err := archive.ParseAttributes(b)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("roundtrip:\n got %+v\nwant %+v", got, want)
		}
	}
}

func TestAttributesRejectInvalid(t *testing.T) {
	for name, a := range map[string]archive.Attributes{
		"unknown kind":           {Kind: 9},
		"mode bits":              {Mode: 0o170000},
		"symlink without target": {Kind: archive.KindSymlink},
		"file with target":       {Kind: archive.KindRegular, LinkTarget: "x"},
		"unsafe hardlink target": {Kind: archive.KindHardlink, LinkTarget: "../escape"},
		"long target":            {Kind: archive.KindSymlink, LinkTarget: strings.Repeat("a", archive.MaxLinkTargetLen+1)},
		"empty xattr name":       {Xattrs: []archive.Xattr{{Name: ""}}},
		"xattrs too large":       {Xattrs: []archive.Xattr{{Name: "user.big", Value: make([]byte, archive.MaxXattrsSize)}}},
	} {
		if _, err := archive.AppendAttributes(nil, a); !errors.Is(err, archive.ErrMalformedAttributes) {
			t.Errorf("%s: want ErrMalformedAttributes, got %v", name, err)
		}
	}
	good, err := archive.AppendAttributes(nil, archive.Attributes{Kind: archive.KindSymlink, Mode: 0o777, LinkTarget: "target",
		Xattrs: []archive.Xattr{{Name: "user.a", Value: []byte("v")}}})
	if err != nil {
		t.Fatal(err)
	}
	flagged := bytes.Clone(good)
	flagged[13] = 0x80
	for name, b := range map[string][]byte{
		"truncated":      good[:len(good)-1],
		"trailing bytes": append(bytes.Clone(good), 0),
		"unknown flag":   flagged,
		"empty":          nil,
	} {
		if _, err := archive.ParseAttributes(b); !errors.Is(err, archive.ErrMalformedAttributes) {
			t.Errorf("%s: want ErrMalformedAttributes, got %v", name, err)
		}
	}
}

func TestMetadataCarriesAttributes(t *testing.T) {
	mm, err := archive.NewMetadataManager([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	attrs := archive.Attributes{Kind: archive.KindSymlink, Mode: 0o777, ModTime: 42, LinkTarget: "target"}
	block, err := mm.Seal(archive.PlaintextMetadata{EncryptedFilename: []byte("name"), Codec: archive.CodecZstd, Attributes: &attrs})
	if err != nil {
		t.Fatal(err)
	}
	pm, err := mm.Open(block)
	if err != nil {
		t.Fatal(err)
	}
	if pm.Attributes == nil || !reflect.DeepEqual(*pm.Attributes, attrs) || pm.Codec != archive.CodecZstd {
		t.Fatalf("attributes lost: %+v", pm)
	}
	plain, err := mm.Seal(archive.PlaintextMetadata{EncryptedFilename: []byte("name")})
	if err != nil {
		t.Fatal(err)
	}
	if pm, err := mm.Open(plain); err != nil || pm.Attributes != nil {
		t.Fatalf("metadata without attributes: %+v %v", pm, err)
	}
}
