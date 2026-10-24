// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive_test

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"errors"
	"reflect"
	"testing"

	"github.com/iamvirul/sarc/archive"
)

func sampleIndex() *archive.SessionIndex {
	return &archive.SessionIndex{
		Session:    3,
		Time:       1_790_000_000,
		PrevIndex:  123456,
		FirstChunk: 40,
		Packs:      []uint64{200000, 9000000},
		Chunks: []archive.ChunkRecord{
			{ID: [32]byte{1}, Pack: 0, Offset: 0, StoredLen: 1000, RawLen: 1000, Codec: archive.CodecNone},
			{ID: [32]byte{2}, Pack: 1, Offset: 4096, StoredLen: 300, RawLen: 900, Codec: archive.CodecZstd},
		},
		Files: []archive.FileVersion{
			{Name: "data/a.txt", Attributes: archive.Attributes{Mode: 0o644, ModTime: 1_790_000_000_123_456_789,
				Xattrs: []archive.Xattr{{Name: "user.tag", Value: []byte("x")}}}, Size: 1900, Chunks: []uint64{40, 41}},
			{Name: "data/same.bin", Attributes: archive.Attributes{Mode: 0o600, ModTime: -5, Owner: &archive.Owner{UID: 1, GID: 2}},
				Size: 1000, Chunks: []uint64{3, 3, 40}},
			{Name: "empty", Attributes: archive.Attributes{Mode: 0o644}, Size: 0, Chunks: []uint64{}},
			{Name: "data", Attributes: archive.Attributes{Kind: archive.KindDirectory, Mode: 0o755}, Chunks: []uint64{}},
			{Name: "data/link", Attributes: archive.Attributes{Kind: archive.KindSymlink, Mode: 0o777, LinkTarget: "a.txt"}, Chunks: []uint64{}},
			{Name: "data/hard", Attributes: archive.Attributes{Kind: archive.KindHardlink, Mode: 0o644, LinkTarget: "data/a.txt"}, Chunks: []uint64{}},
		},
		Deleted: []string{"data/old.txt"},
	}
}

func TestSessionIndexRoundtrip(t *testing.T) {
	want := sampleIndex()
	b, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := archive.ParseSessionIndex(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("roundtrip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseSessionIndexRejectsMalformed(t *testing.T) {
	mutate := map[string]func(si *archive.SessionIndex){
		"reference to a future chunk": func(si *archive.SessionIndex) { si.Files[0].Chunks = []uint64{42} },
		"chunk in unknown pack":       func(si *archive.SessionIndex) { si.Chunks[0].Pack = 2 },
		"oversized chunk":             func(si *archive.SessionIndex) { si.Chunks[0].RawLen = archive.MaxCDCChunkSize + 1 },
		"chunk past pack end":         func(si *archive.SessionIndex) { si.Chunks[0].Offset = archive.MaxPackSize },
		"unknown codec":               func(si *archive.SessionIndex) { si.Chunks[0].Codec = 9 },
		"raw chunk size mismatch":     func(si *archive.SessionIndex) { si.Chunks[0].StoredLen = 999 },
		"session zero":                func(si *archive.SessionIndex) { si.Session = 0 },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			si := sampleIndex()
			m(si)
			b, err := si.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := archive.ParseSessionIndex(b); !errors.Is(err, archive.ErrMalformedIndex) {
				t.Fatalf("want ErrMalformedIndex, got %v", err)
			}
		})
	}
	good, err := sampleIndex().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string][]byte{
		"bad magic":      append([]byte("XXXXIDX1"), good[8:]...),
		"truncated":      good[:len(good)-3],
		"trailing bytes": append(bytes.Clone(good), 0),
		"huge count":     append([]byte("SARCIDX1\x01\x02\x00\x00"), 0xFF, 0xFF, 0xFF, 0xFF, 0x0F),
		"empty":          nil,
	}
	for name, b := range raw {
		if _, err := archive.ParseSessionIndex(b); !errors.Is(err, archive.ErrMalformedIndex) {
			t.Fatalf("%s: want ErrMalformedIndex, got %v", name, err)
		}
	}
}

func TestSessionIndexRejectsUnsafeNames(t *testing.T) {
	si := sampleIndex()
	si.Files[0].Name = "../escape"
	if _, err := si.Marshal(); err == nil {
		t.Fatal("unsafe file name marshaled")
	}
	si = sampleIndex()
	si.Deleted = []string{"/abs"}
	if _, err := si.Marshal(); err == nil {
		t.Fatal("unsafe deleted name marshaled")
	}
}

func TestCheckpointRoundtrip(t *testing.T) {
	state, err := sha256.New().(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := archive.Checkpoint{LastIndex: 987654321, HashState: state}
	b, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != archive.CheckpointSize {
		t.Fatalf("checkpoint is %d bytes, want %d", len(b), archive.CheckpointSize)
	}
	got, err := archive.ParseCheckpoint(b)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("roundtrip: %+v %v", got, err)
	}
	b[1] ^= 1
	if _, err := archive.ParseCheckpoint(b); !errors.Is(err, archive.ErrMalformedCheckpoint) {
		t.Fatalf("corrupt magic: want ErrMalformedCheckpoint, got %v", err)
	}
}

// TestResumedWriterExtendsChecksum checks that a footer written after resuming from a
// checkpoint equals SHA-256 over every byte before it, as if written in one pass.
func TestResumedWriterExtendsChecksum(t *testing.T) {
	var first bytes.Buffer
	aw, err := archive.NewArchiveWriter(&first, archive.Credentials{Passwords: []string{"resume-test"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteHeaderWithFlags(1, archive.HeaderFlagIncremental); err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteCheckpointFooter(42); err != nil {
		t.Fatal(err)
	}
	data := first.Bytes()
	tailStart := len(data) - archive.TailSize
	cp, err := archive.ParseCheckpoint(data[tailStart : tailStart+archive.CheckpointSize])
	if err != nil {
		t.Fatal(err)
	}
	if cp.LastIndex != 42 {
		t.Fatalf("last index %d", cp.LastIndex)
	}

	var appended bytes.Buffer
	appended.Write(data[:tailStart])
	resumed, err := archive.ResumeArchiveWriter(&appended, aw.Keys(), int64(tailStart), cp.HashState)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Offset() != int64(tailStart) {
		t.Fatalf("resumed offset %d, want %d", resumed.Offset(), tailStart)
	}
	if err := resumed.WriteCheckpointFooter(77); err != nil {
		t.Fatal(err)
	}
	out := appended.Bytes()
	body := out[:len(out)-archive.FooterSize]
	sum := archive.NewArchiveChecksum()
	sum.Write(body)
	if !bytes.Equal(out[len(body):len(body)+32], sum.Sum(nil)) {
		t.Fatal("resumed footer is not the checksum of the whole archive body")
	}
}

func checksumOf(b []byte) []byte {
	sum := archive.NewArchiveChecksum()
	// Feed in small pieces to exercise holding back the header.
	for len(b) > 0 {
		n := min(len(b), 7)
		sum.Write(b[:n])
		b = b[n:]
	}
	return sum.Sum(nil)
}

// TestArchiveChecksumMasksOnlyTheIncrementalSessionCount checks that rewriting an
// incremental header's sealed count leaves the checksum unchanged, any other change
// does not, and a normal archive hashes as plain SHA-256.
func TestArchiveChecksumMasksOnlyTheIncrementalSessionCount(t *testing.T) {
	for _, flags := range []byte{0, archive.HeaderFlagIncremental} {
		var buf bytes.Buffer
		aw, err := archive.NewArchiveWriter(&buf, archive.Credentials{Passwords: []string{"mask-test"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := aw.WriteHeaderWithFlags(1, flags); err != nil {
			t.Fatal(err)
		}
		if err := aw.WriteFooter(); err != nil {
			t.Fatal(err)
		}
		data := buf.Bytes()
		body := data[:len(data)-archive.FooterSize]
		stored := data[len(body) : len(body)+32]
		if !bytes.Equal(checksumOf(body), stored) {
			t.Fatalf("flags %d: footer does not match the checksum", flags)
		}
		plain := sha256.Sum256(body)
		if (flags == 0) != bytes.Equal(plain[:], stored) {
			t.Fatalf("flags %d: plain SHA-256 match is %v", flags, bytes.Equal(plain[:], stored))
		}

		resealed := bytes.Clone(body)
		off := aw.FileCountOffset()
		sealed, err := archive.SealFileCount(aw.Keys(), 9)
		if err != nil {
			t.Fatal(err)
		}
		copy(resealed[off:], sealed[:])
		if got := bytes.Equal(checksumOf(resealed), stored); got != (flags != 0) {
			t.Fatalf("flags %d: checksum unchanged after resealing the count is %v", flags, got)
		}
		tampered := bytes.Clone(body)
		tampered[len(tampered)-1] ^= 1
		if bytes.Equal(checksumOf(tampered), stored) {
			t.Fatalf("flags %d: checksum unchanged after modifying the body", flags)
		}
	}
}

func TestHeaderFlagsAndFileCountOffset(t *testing.T) {
	var buf bytes.Buffer
	aw, err := archive.NewArchiveWriter(&buf, archive.Credentials{Passwords: []string{"flags-test"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteHeaderWithFlags(5, archive.HeaderFlagIncremental); err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteFooter(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	off := aw.FileCountOffset()
	if b[off+archive.FileCountSealedSize] != archive.HeaderFlagIncremental {
		t.Fatal("incremental flag not in the first reserved byte")
	}
	resealed, err := archive.SealFileCount(aw.Keys(), 6)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(resealed[:], b[off:off+archive.FileCountSealedSize]) {
		t.Fatal("resealed count equals the original")
	}
}
