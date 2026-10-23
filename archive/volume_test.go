// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/iamvirul/sarc/archive"
)

func TestVolumeHeaderRoundtrip(t *testing.T) {
	for _, want := range []archive.VolumeHeader{
		{ArchiveID: [16]byte{1, 2, 3}, Index: 1, PayloadLen: 2_000_000_000},
		{ArchiveID: [16]byte{9}, Index: 3, Last: true, PayloadLen: 17},
	} {
		b := want.Marshal()
		if len(b) != archive.VolumeHeaderSize || !archive.IsVolumeHeader(b) {
			t.Fatalf("encoded header is %d bytes", len(b))
		}
		got, err := archive.ParseVolumeHeader(b)
		if err != nil || got != want {
			t.Fatalf("roundtrip: %+v %v", got, err)
		}
	}
}

func TestParseVolumeHeaderRejectsMalformed(t *testing.T) {
	good := archive.VolumeHeader{Index: 2, PayloadLen: 10}.Marshal()
	mutate := func(i int, v byte) []byte {
		b := bytes.Clone(good)
		b[i] = v
		return b
	}
	for name, b := range map[string][]byte{
		"short":         good[:len(good)-1],
		"bad magic":     mutate(0, 'X'),
		"unknown flag":  mutate(28, 0x02),
		"reserved byte": mutate(29, 1),
		"index zero":    archive.VolumeHeader{Index: 0}.Marshal(),
	} {
		if _, err := archive.ParseVolumeHeader(b); !errors.Is(err, archive.ErrMalformedVolumeHeader) {
			t.Errorf("%s: want ErrMalformedVolumeHeader, got %v", name, err)
		}
	}
	if archive.IsVolumeHeader([]byte("SARC\x02\x00")) {
		t.Fatal("an archive header looks like a volume header")
	}
}
