// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/iamvirul/sarc/crypto"
)

// Known-answer vectors computed with an independent RFC 5869 HKDF-Expand implementation.
// A change here means every Version2 archive becomes unreadable.
const (
	kaFileSubkeyHex   = "00787eb7c64f0d689f61814ff0d055061f3c5004f736ce6bdc1bf463c7bcc08b"
	kaHeaderSubkeyHex = "79975d711e821d5be26006c07ae742f14be8096b5a4f400a4fd364047fb2ab07"
)

func knownAnswerInputs() ([crypto.KeySize]byte, [crypto.SaltSize]byte) {
	var master [crypto.KeySize]byte
	for i := range master {
		master[i] = byte(i)
	}
	var salt [crypto.SaltSize]byte
	copy(salt[:], bytes.Repeat([]byte{0xA5}, crypto.SaltSize))
	return master, salt
}

func TestDeriveFileSubkeyKnownAnswer(t *testing.T) {
	master, salt := knownAnswerInputs()
	got, err := crypto.DeriveFileSubkey(master, salt)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != kaFileSubkeyHex {
		t.Fatalf("file subkey mismatch: got %x want %s", got, kaFileSubkeyHex)
	}
}

func TestDeriveHeaderSubkeyKnownAnswer(t *testing.T) {
	master, _ := knownAnswerInputs()
	got, err := crypto.DeriveHeaderSubkey(master)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != kaHeaderSubkeyHex {
		t.Fatalf("header subkey mismatch: got %x want %s", got, kaHeaderSubkeyHex)
	}
}

func TestDeriveFileSubkeyDifferentSaltsProduceDifferentKeys(t *testing.T) {
	master, _ := knownAnswerInputs()
	s1, _ := crypto.GenerateSalt()
	s2, _ := crypto.GenerateSalt()
	k1, err := crypto.DeriveFileSubkey(master, s1)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := crypto.DeriveFileSubkey(master, s2)
	if err != nil {
		t.Fatal(err)
	}
	if k1 == k2 {
		t.Fatal("different salts produced identical file subkeys")
	}
}

func TestDeriveFileSubkeyDifferentMastersProduceDifferentKeys(t *testing.T) {
	m1, salt := knownAnswerInputs()
	m2 := m1
	m2[0] ^= 0x01
	k1, err := crypto.DeriveFileSubkey(m1, salt)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := crypto.DeriveFileSubkey(m2, salt)
	if err != nil {
		t.Fatal(err)
	}
	if k1 == k2 {
		t.Fatal("different master keys produced identical file subkeys")
	}
}

func TestSubkeysNeverEqualMasterKey(t *testing.T) {
	master, salt := knownAnswerInputs()
	fk, err := crypto.DeriveFileSubkey(master, salt)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := crypto.DeriveHeaderSubkey(master)
	if err != nil {
		t.Fatal(err)
	}
	if fk == master || hk == master || fk == hk {
		t.Fatal("subkeys are not domain-separated from each other and the master key")
	}
}
