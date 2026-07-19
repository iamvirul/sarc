// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

func TestMetadataSealOpenRoundtrip(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	key := crypto.NewKeyDeriver("testpassword").DeriveKey(salt)
	mm, err := archive.NewMetadataManager(key)
	if err != nil {
		t.Fatal(err)
	}

	want := archive.PlaintextMetadata{
		EncryptedFilename: []byte("encrypted-name-blob"),
		SizeBucket:        archive.BucketMedium,
		TimestampHash:     archive.HashTimestamp(salt, time.Now()),
		Permissions:       0o644,
	}

	block, err := mm.Seal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := mm.Open(block)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.EncryptedFilename, want.EncryptedFilename) {
		t.Fatalf("filename mismatch")
	}
	if got.SizeBucket != want.SizeBucket {
		t.Fatalf("size bucket mismatch: got %d want %d", got.SizeBucket, want.SizeBucket)
	}
	if got.TimestampHash != want.TimestampHash {
		t.Fatalf("timestamp hash mismatch")
	}
	if got.Permissions != want.Permissions {
		t.Fatalf("permissions mismatch: got %o want %o", got.Permissions, want.Permissions)
	}
}

func TestMetadataTamperedBlockFails(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	key := crypto.NewKeyDeriver("testpassword").DeriveKey(salt)
	mm, _ := archive.NewMetadataManager(key)

	block, _ := mm.Seal(archive.PlaintextMetadata{SizeBucket: archive.BucketTiny})
	block.Ciphertext[0] ^= 0xFF

	if _, err := mm.Open(block); err == nil {
		t.Fatal("expected error on tampered metadata block, got nil")
	}
}

func TestBucketizeSizeBoundaries(t *testing.T) {
	cases := []struct {
		size   int64
		bucket archive.SizeBucket
	}{
		{0, archive.BucketTiny},
		{1024, archive.BucketTiny},
		{1025, archive.BucketSmall},
		{10240, archive.BucketSmall},
		{10241, archive.BucketMedium},
		{102400, archive.BucketMedium},
		{102401, archive.BucketLarge},
		{1048576, archive.BucketLarge},
		{1048577, archive.BucketHuge},
	}
	for _, c := range cases {
		got := archive.BucketizeSize(c.size)
		if got != c.bucket {
			t.Errorf("BucketizeSize(%d) = %d, want %d", c.size, got, c.bucket)
		}
	}
}

func TestHashTimestampIsDeterministic(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	ts := time.Date(2026, 7, 1, 15, 30, 0, 0, time.UTC)
	h1 := archive.HashTimestamp(salt, ts)
	h2 := archive.HashTimestamp(salt, ts)
	if h1 != h2 {
		t.Fatal("HashTimestamp is not deterministic")
	}
}

func TestHashTimestampDayTruncation(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	t1 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 7, 1, 23, 59, 59, 0, time.UTC)
	if archive.HashTimestamp(salt, t1) != archive.HashTimestamp(salt, t2) {
		t.Fatal("timestamps on the same day produced different hashes")
	}
}

func TestArchiveWriterHeaderMagicAndVersion(t *testing.T) {
	var buf bytes.Buffer
	salt, _ := crypto.GenerateSalt()
	aw, err := archive.NewArchiveWriter(&buf, "password", salt)
	if err != nil {
		t.Fatal(err)
	}
	hdr := archive.ArchiveHeader{
		Magic:       archive.Magic,
		Version:     archive.Version,
		ArchiveSalt: salt,
	}
	if err := aw.WriteHeader(hdr, 3); err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteFooter(); err != nil {
		t.Fatal(err)
	}

	out := buf.Bytes()
	if out[0] != 'S' || out[1] != 'A' || out[2] != 'R' || out[3] != 'C' {
		t.Fatalf("magic mismatch in output: %q", out[:4])
	}
}
