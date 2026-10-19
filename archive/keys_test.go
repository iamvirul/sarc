// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive_test

import (
	"errors"
	"testing"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

const keysTestPassword = "key-schedule-password"

func testCEK(t *testing.T) [crypto.KeySize]byte {
	t.Helper()
	cek, err := crypto.GenerateCEK()
	if err != nil {
		t.Fatal(err)
	}
	return cek
}

func TestKeyScheduleVersion2FileKeyIsHKDFOfCEK(t *testing.T) {
	cek := testCEK(t)
	entrySalt, _ := crypto.GenerateSalt()

	got, err := archive.NewVersion2KeySchedule(cek).FileKey(entrySalt)
	if err != nil {
		t.Fatal(err)
	}
	want, err := crypto.DeriveFileSubkey(cek, entrySalt)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("version 2 file key is not HKDF-Expand(CEK, entry_salt)")
	}
}

func TestKeyScheduleVersion1FileKeyIsPBKDF2OfEntrySalt(t *testing.T) {
	entrySalt, _ := crypto.GenerateSalt()
	got, err := archive.NewVersion1KeySchedule(keysTestPassword).FileKey(entrySalt)
	if err != nil {
		t.Fatal(err)
	}
	if want := crypto.NewKeyDeriver(keysTestPassword).DeriveKey(entrySalt); got != want {
		t.Fatal("version 1 file key is not PBKDF2(password, entry_salt)")
	}
}

func TestKeyScheduleVersion2DistinctEntriesGetDistinctKeys(t *testing.T) {
	ks := archive.NewVersion2KeySchedule(testCEK(t))
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

func TestKeyScheduleVersion2DifferentCEKsGiveDifferentKeys(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	k1, err := archive.NewVersion2KeySchedule(testCEK(t)).FileKey(salt)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := archive.NewVersion2KeySchedule(testCEK(t)).FileKey(salt)
	if err != nil {
		t.Fatal(err)
	}
	if k1 == k2 {
		t.Fatal("two archives with different CEKs derived the same file key")
	}
}

func TestKeyScheduleVersion1HasNoHeaderKey(t *testing.T) {
	if _, err := archive.NewVersion1KeySchedule(keysTestPassword).HeaderKey(); !errors.Is(err, archive.ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
}

func TestKeyScheduleVersion2HeaderKeyDiffersFromFileKeysAndCEK(t *testing.T) {
	cek := testCEK(t)
	ks := archive.NewVersion2KeySchedule(cek)
	hk, err := ks.HeaderKey()
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := crypto.GenerateSalt()
	fk, err := ks.FileKey(salt)
	if err != nil {
		t.Fatal(err)
	}
	if hk == fk || hk == cek || fk == cek {
		t.Fatal("header key, file key, and CEK are not domain-separated")
	}
}

func TestKeyScheduleVersions(t *testing.T) {
	if v := archive.NewVersion1KeySchedule(keysTestPassword).Version(); v != archive.Version1 {
		t.Fatalf("v1 schedule reports version %d", v)
	}
	if v := archive.NewVersion2KeySchedule(testCEK(t)).Version(); v != archive.Version2 {
		t.Fatalf("v2 schedule reports version %d", v)
	}
}
