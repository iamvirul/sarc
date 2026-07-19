// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto_test

import (
	"bytes"
	"testing"

	"github.com/iamvirul/sarc/crypto"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	key := crypto.NewKeyDeriver("password123").DeriveKey(salt)
	em, err := crypto.NewEncryptionManager(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello sarc")
	block, err := em.EncryptBlock(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := em.DecryptBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plaintext)
	}
}

func TestEncryptProducesUniqueOutputs(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	key := crypto.NewKeyDeriver("password123").DeriveKey(salt)
	em, _ := crypto.NewEncryptionManager(key)

	plaintext := []byte("duplicate content")
	b1, _ := em.EncryptBlock(plaintext)
	b2, _ := em.EncryptBlock(plaintext)

	if bytes.Equal(b1.Nonce[:], b2.Nonce[:]) {
		t.Fatal("nonce reuse detected across two EncryptBlock calls")
	}
	if bytes.Equal(b1.Ciphertext, b2.Ciphertext) {
		t.Fatal("identical ciphertext produced for same plaintext (nonce not random)")
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	key := crypto.NewKeyDeriver("password123").DeriveKey(salt)
	em, _ := crypto.NewEncryptionManager(key)

	block, _ := em.EncryptBlock([]byte("sensitive data"))
	block.Ciphertext[0] ^= 0xFF

	if _, err := em.DecryptBlock(block); err == nil {
		t.Fatal("expected error on tampered ciphertext, got nil")
	}
}

func TestKeyDerivationIsDeterministic(t *testing.T) {
	kd := crypto.NewKeyDeriver("mypassword")
	var salt [crypto.SaltSize]byte
	copy(salt[:], bytes.Repeat([]byte{0xAB}, crypto.SaltSize))

	k1 := kd.DeriveKey(salt)
	k2 := kd.DeriveKey(salt)
	if k1 != k2 {
		t.Fatal("key derivation is not deterministic")
	}
}

func TestDifferentSaltsProduceDifferentKeys(t *testing.T) {
	kd := crypto.NewKeyDeriver("mypassword")
	s1, _ := crypto.GenerateSalt()
	s2, _ := crypto.GenerateSalt()

	if kd.DeriveKey(s1) == kd.DeriveKey(s2) {
		t.Fatal("different salts produced identical keys")
	}
}

func TestHMACVerifyAcceptsValidTag(t *testing.T) {
	var key [crypto.KeySize]byte
	copy(key[:], bytes.Repeat([]byte{0x01}, crypto.KeySize))
	data := []byte("important data")
	tag := crypto.ComputeHMAC(key, data)
	if err := crypto.VerifyHMAC(key, data, tag); err != nil {
		t.Fatalf("valid HMAC rejected: %v", err)
	}
}

func TestHMACVerifyRejectsModifiedData(t *testing.T) {
	var key [crypto.KeySize]byte
	copy(key[:], bytes.Repeat([]byte{0x02}, crypto.KeySize))
	data := []byte("important data")
	tag := crypto.ComputeHMAC(key, data)

	tampered := append([]byte(nil), data...)
	tampered[0] ^= 0x01
	if err := crypto.VerifyHMAC(key, tampered, tag); err == nil {
		t.Fatal("modified data accepted by HMAC verify")
	}
}

func TestPaddingRanges(t *testing.T) {
	pm := crypto.NewPaddingManager()
	for i := 0; i < 20; i++ {
		hdr, err := pm.Header()
		if err != nil {
			t.Fatal(err)
		}
		if len(hdr) < crypto.HeaderPadMin || len(hdr) > crypto.HeaderPadMax {
			t.Fatalf("header padding %d out of range [%d, %d]", len(hdr), crypto.HeaderPadMin, crypto.HeaderPadMax)
		}
		trl, err := pm.Trailer()
		if err != nil {
			t.Fatal(err)
		}
		if len(trl) < crypto.TrailerPadMin || len(trl) > crypto.TrailerPadMax {
			t.Fatalf("trailer padding %d out of range [%d, %d]", len(trl), crypto.TrailerPadMin, crypto.TrailerPadMax)
		}
	}
}

func TestEncryptStreamRoundtrip(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	key := crypto.NewKeyDeriver("password123").DeriveKey(salt)
	em, _ := crypto.NewEncryptionManager(key)

	content := bytes.Repeat([]byte("ABCD"), 40*1024) // ~160 KB
	blocks, err := em.EncryptStream(bytes.NewReader(content), crypto.NewRandomVarianceGenerator(8192))
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) < 2 {
		t.Fatalf("expected multiple blocks for 160 KB content, got %d", len(blocks))
	}

	var recovered bytes.Buffer
	for _, b := range blocks {
		pt, err := em.DecryptBlock(b)
		if err != nil {
			t.Fatal(err)
		}
		recovered.Write(pt)
	}
	if !bytes.Equal(recovered.Bytes(), content) {
		t.Fatal("stream roundtrip content mismatch")
	}
}
