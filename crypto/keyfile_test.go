// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/iamvirul/sarc/crypto"
)

func mustKeyFile(t *testing.T, size int) []byte {
	t.Helper()
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestKeyFileWrapRoundtrip(t *testing.T) {
	cek := mustCEK(t)
	key := mustKeyFile(t, crypto.MinKeyFileSize)
	w, err := crypto.WrapCEKWithKeyFile(cek, key)
	if err != nil {
		t.Fatal(err)
	}
	other := mustKeyFile(t, 4096)
	got, err := crypto.UnwrapCEKWithKeyFile(w, [][]byte{other, key})
	if err != nil {
		t.Fatal(err)
	}
	if got != cek {
		t.Fatal("unwrapped CEK differs")
	}
}

func TestKeyFileWrapRejectsWrongOrTamperedKey(t *testing.T) {
	key := mustKeyFile(t, 64)
	w, err := crypto.WrapCEKWithKeyFile(mustCEK(t), key)
	if err != nil {
		t.Fatal(err)
	}
	flipped := bytes.Clone(key)
	flipped[len(flipped)-1] ^= 1
	for name, keys := range map[string][][]byte{
		"different key": {mustKeyFile(t, 64)},
		"one bit off":   {flipped},
		"truncated key": {key[:crypto.MinKeyFileSize]},
		"no keys":       nil,
	} {
		if _, err := crypto.UnwrapCEKWithKeyFile(w, keys); !errors.Is(err, crypto.ErrWrongCredential) {
			t.Fatalf("%s: want ErrWrongCredential, got %v", name, err)
		}
	}
	w.Sealed[0] ^= 1
	if _, err := crypto.UnwrapCEKWithKeyFile(w, [][]byte{key}); !errors.Is(err, crypto.ErrWrongCredential) {
		t.Fatalf("tampered wrap: want ErrWrongCredential, got %v", err)
	}
}

func TestKeyFileWrapEnforcesKeySize(t *testing.T) {
	for _, size := range []int{0, crypto.MinKeyFileSize - 1, crypto.MaxKeyFileSize + 1} {
		if _, err := crypto.WrapCEKWithKeyFile(mustCEK(t), make([]byte, size)); !errors.Is(err, crypto.ErrKeyFileSize) {
			t.Fatalf("size %d: want ErrKeyFileSize, got %v", size, err)
		}
		if _, err := crypto.WrapCEKWithKeyFileAndPassword(mustCEK(t), make([]byte, size), "password"); !errors.Is(err, crypto.ErrKeyFileSize) {
			t.Fatalf("size %d with password: want ErrKeyFileSize, got %v", size, err)
		}
	}
}

func TestKeyFileWrapsAreRandomized(t *testing.T) {
	cek, key := mustCEK(t), mustKeyFile(t, 32)
	a, err := crypto.WrapCEKWithKeyFile(cek, key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypto.WrapCEKWithKeyFile(cek, key)
	if err != nil {
		t.Fatal(err)
	}
	if a.Salt == b.Salt || a.Nonce == b.Nonce || a.Sealed == b.Sealed {
		t.Fatal("two wraps of the same CEK and key share salt, nonce, or ciphertext")
	}
}

func TestKeyFileAndPasswordWrapNeedsBoth(t *testing.T) {
	cek, key := mustCEK(t), mustKeyFile(t, 32)
	w, err := crypto.WrapCEKWithKeyFileAndPassword(cek, key, "second-factor")
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.UnwrapCEKWithKeyFileAndPassword(w, [][]byte{mustKeyFile(t, 32), key}, "second-factor")
	if err != nil {
		t.Fatal(err)
	}
	if got != cek {
		t.Fatal("unwrapped CEK differs")
	}
	for name, attempt := range map[string]struct {
		keys     [][]byte
		password string
	}{
		"key without password": {[][]byte{key}, ""},
		"key, wrong password":  {[][]byte{key}, "wrong-factor"},
		"password without key": {nil, "second-factor"},
		"password, wrong key":  {[][]byte{mustKeyFile(t, 32)}, "second-factor"},
	} {
		if _, err := crypto.UnwrapCEKWithKeyFileAndPassword(w, attempt.keys, attempt.password); !errors.Is(err, crypto.ErrWrongCredential) {
			t.Fatalf("%s: want ErrWrongCredential, got %v", name, err)
		}
	}
	// The password alone must not open it as a plain password wrap either.
	if _, err := crypto.UnwrapCEKWithPassword(w, "second-factor"); !errors.Is(err, crypto.ErrWrongCredential) {
		t.Fatalf("combined wrap opened as a password wrap: %v", err)
	}
}

func TestKeyFileAndPasswordWrapRejectsEmptyPassword(t *testing.T) {
	if _, err := crypto.WrapCEKWithKeyFileAndPassword(mustCEK(t), mustKeyFile(t, 32), ""); err == nil {
		t.Fatal("empty password accepted")
	}
}

func TestKeyFileAndPasswordWrapBoundsIterations(t *testing.T) {
	key := mustKeyFile(t, 32)
	w, err := crypto.WrapCEKWithKeyFileAndPassword(mustCEK(t), key, "second-factor")
	if err != nil {
		t.Fatal(err)
	}
	for _, iterations := range []uint32{0, crypto.MinPasswordIterations - 1, crypto.MaxPasswordIterations + 1} {
		w.Iterations = iterations
		_, err := crypto.UnwrapCEKWithKeyFileAndPassword(w, [][]byte{key}, "second-factor")
		if err == nil || errors.Is(err, crypto.ErrWrongCredential) {
			t.Fatalf("iterations %d: want range error, got %v", iterations, err)
		}
	}
}
