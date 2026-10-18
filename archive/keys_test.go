// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

const keysTestPassword = "key-schedule-password"

func TestKeyScheduleVersion2FileKeyIsHKDFOfMasterKey(t *testing.T) {
	archiveSalt, _ := crypto.GenerateSalt()
	entrySalt, _ := crypto.GenerateSalt()

	ks, err := archive.NewKeySchedule(keysTestPassword, archive.Version2, archiveSalt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ks.FileKey(entrySalt)
	if err != nil {
		t.Fatal(err)
	}

	master := crypto.NewKeyDeriver(keysTestPassword).DeriveKey(archiveSalt)
	want, err := crypto.DeriveFileSubkey(master, entrySalt)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("version 2 file key is not HKDF-Expand(PBKDF2(password, archive_salt), entry_salt)")
	}
}

func TestKeyScheduleVersion1FileKeyIsPBKDF2OfEntrySalt(t *testing.T) {
	archiveSalt, _ := crypto.GenerateSalt()
	entrySalt, _ := crypto.GenerateSalt()

	ks, err := archive.NewKeySchedule(keysTestPassword, archive.Version1, archiveSalt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ks.FileKey(entrySalt)
	if err != nil {
		t.Fatal(err)
	}
	if want := crypto.NewKeyDeriver(keysTestPassword).DeriveKey(entrySalt); got != want {
		t.Fatal("version 1 file key is not PBKDF2(password, entry_salt)")
	}
}

func TestKeyScheduleVersion2DistinctEntriesGetDistinctKeys(t *testing.T) {
	archiveSalt, _ := crypto.GenerateSalt()
	ks, err := archive.NewKeySchedule(keysTestPassword, archive.Version2, archiveSalt)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[[crypto.KeySize]byte]bool, 64)
	for i := 0; i < 64; i++ {
		salt, _ := crypto.GenerateSalt()
		key, err := ks.FileKey(salt)
		if err != nil {
			t.Fatal(err)
		}
		if seen[key] {
			t.Fatalf("file key collision at entry %d", i)
		}
		seen[key] = true
	}
}

func TestKeyScheduleRejectsUnknownVersion(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	for _, v := range []uint16{0, archive.Version + 1, 0xFFFF} {
		if _, err := archive.NewKeySchedule(keysTestPassword, v, salt); !errors.Is(err, archive.ErrUnsupportedVersion) {
			t.Fatalf("version %d: want ErrUnsupportedVersion, got %v", v, err)
		}
	}
}

func TestKeyScheduleVersion1HasNoHeaderKey(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	ks, err := archive.NewKeySchedule(keysTestPassword, archive.Version1, salt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.HeaderKey(); !errors.Is(err, archive.ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
}

func TestKeyScheduleVersion2HeaderKeyDiffersFromFileKeys(t *testing.T) {
	archiveSalt, _ := crypto.GenerateSalt()
	ks, err := archive.NewKeySchedule(keysTestPassword, archive.Version2, archiveSalt)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := ks.HeaderKey()
	if err != nil {
		t.Fatal(err)
	}
	fk, err := ks.FileKey(archiveSalt)
	if err != nil {
		t.Fatal(err)
	}
	if hk == fk {
		t.Fatal("header key equals file key derived from the same salt")
	}
}

func TestArchiveWriterRejectsHeaderVersionMismatch(t *testing.T) {
	var buf bytes.Buffer
	salt, _ := crypto.GenerateSalt()
	aw, err := archive.NewArchiveWriter(&buf, keysTestPassword, salt)
	if err != nil {
		t.Fatal(err)
	}
	hdr := archive.ArchiveHeader{Magic: archive.Magic, Version: archive.Version1, ArchiveSalt: salt}
	if err := aw.WriteHeader(hdr, 0); !errors.Is(err, archive.ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("rejected header still wrote %d bytes", buf.Len())
	}
}
