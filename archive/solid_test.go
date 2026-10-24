// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/iamvirul/sarc/archive"
)

func TestSolidStreamRoundtrip(t *testing.T) {
	members := []archive.SolidMember{
		{Name: "main.go", Attributes: archive.Attributes{Mode: 0o644, ModTime: 1_790_000_000_000_000_001}, Data: []byte("package main\n")},
		{Name: "empty.txt", Attributes: archive.Attributes{Mode: 0o600}, Data: nil},
		{Name: "run.sh", Attributes: archive.Attributes{Mode: 0o4755, Owner: &archive.Owner{UID: 1000, GID: 50},
			Xattrs: []archive.Xattr{{Name: "user.note", Value: []byte("v")}}}, Data: bytes.Repeat([]byte{0x00, 0xFF}, 5000)},
		{Name: strings.Repeat("n", 0xFFFF), Attributes: archive.Attributes{Mode: 0o644}, Data: []byte("max name")},
	}
	var stream []byte
	for _, m := range members {
		var err error
		if stream, err = archive.AppendSolidRecord(stream, m); err != nil {
			t.Fatal(err)
		}
	}
	wantLen := 0
	for _, m := range members {
		attrs, err := archive.AppendAttributes(nil, m.Attributes)
		if err != nil {
			t.Fatal(err)
		}
		wantLen += archive.SolidRecordSize(len(m.Name), len(attrs), len(m.Data))
	}
	if len(stream) != wantLen {
		t.Fatalf("stream length %d, SolidRecordSize sum %d", len(stream), wantLen)
	}

	got, err := archive.ParseSolidStream(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(members) {
		t.Fatalf("got %d members, want %d", len(got), len(members))
	}
	for i, m := range members {
		if got[i].Name != m.Name || !reflect.DeepEqual(got[i].Attributes, m.Attributes) || !bytes.Equal(got[i].Data, m.Data) {
			t.Fatalf("member %d mismatch", i)
		}
	}
}

func TestAppendSolidRecordRejectsInvalidName(t *testing.T) {
	if _, err := archive.AppendSolidRecord(nil, archive.SolidMember{Name: "../etc/passwd"}); err == nil {
		t.Fatal("path-traversal member name accepted")
	}
}

// rawRecord encodes a record without name validation, for malformed-stream tests.
func rawRecord(name string, dataLen uint64, data []byte) []byte {
	attrs, _ := archive.AppendAttributes(nil, archive.Attributes{Mode: 0o644})
	var b []byte
	b = binary.LittleEndian.AppendUint16(b, uint16(len(name)))
	b = append(b, name...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(attrs)))
	b = append(b, attrs...)
	b = binary.LittleEndian.AppendUint64(b, dataLen)
	return append(b, data...)
}

func TestAppendSolidRecordRejectsNonRegularMembers(t *testing.T) {
	m := archive.SolidMember{Name: "link", Attributes: archive.Attributes{Kind: archive.KindSymlink, LinkTarget: "x"}}
	if _, err := archive.AppendSolidRecord(nil, m); err == nil {
		t.Fatal("symlink packed into a solid group")
	}
}

func TestParseSolidStreamRejectsMalformedInput(t *testing.T) {
	valid := rawRecord("ok.txt", 2, []byte("hi"))
	cases := map[string][]byte{
		"empty stream":           nil,
		"truncated name length":  {0x05},
		"truncated header":       valid[:6],
		"data runs past stream":  rawRecord("a.txt", 100, []byte("short")),
		"huge data length":       rawRecord("a.txt", 1<<63, nil),
		"dot-dot name":           rawRecord("..", 0, nil),
		"path separator in name": rawRecord("x/../../evil", 0, nil),
		"empty name":             rawRecord("", 0, nil),
		"trailing garbage":       append(append([]byte{}, valid...), 0x01),
	}
	for name, stream := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := archive.ParseSolidStream(stream); !errors.Is(err, archive.ErrMalformedSolidStream) {
				t.Fatalf("want ErrMalformedSolidStream, got %v", err)
			}
		})
	}
}

func TestSolidCodecRoundtripAtMaxStreamSize(t *testing.T) {
	bc, err := archive.NewSolidCompressor(archive.DefaultCompressionLevel)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := archive.NewSolidDecompressor()
	if err != nil {
		t.Fatal(err)
	}
	defer bd.Close()

	line := []byte("solid stream content shared across members\n")
	stream := bytes.Repeat(line, archive.MaxSolidStreamSize/len(line)+1)[:archive.MaxSolidStreamSize]
	got, err := bd.Decompress(bc.Compress(nil, stream))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, stream) {
		t.Fatal("max-size solid stream roundtrip mismatch")
	}
}

func TestSolidDecompressorRejectsStreamAboveLimit(t *testing.T) {
	bc, err := archive.NewSolidCompressor(archive.DefaultCompressionLevel)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := archive.NewSolidDecompressor()
	if err != nil {
		t.Fatal(err)
	}
	defer bd.Close()
	bomb := bc.Compress(nil, make([]byte, archive.MaxSolidStreamSize+1))
	if _, err := bd.Decompress(bomb); !errors.Is(err, archive.ErrBlockTooLarge) {
		t.Fatalf("want ErrBlockTooLarge, got %v", err)
	}
}

func TestNewSolidCompressorRejectsInvalidLevel(t *testing.T) {
	if _, err := archive.NewSolidCompressor(0); !errors.Is(err, archive.ErrInvalidCompressionLevel) {
		t.Fatalf("want ErrInvalidCompressionLevel, got %v", err)
	}
}
