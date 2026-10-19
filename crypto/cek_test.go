// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto_test

import (
	"errors"
	"testing"

	"filippo.io/age"

	"github.com/iamvirul/sarc/crypto"
)

func mustCEK(t *testing.T) [crypto.KeySize]byte {
	t.Helper()
	cek, err := crypto.GenerateCEK()
	if err != nil {
		t.Fatal(err)
	}
	return cek
}

func mustIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestGenerateCEKIsRandom(t *testing.T) {
	if mustCEK(t) == mustCEK(t) {
		t.Fatal("two generated CEKs are identical")
	}
}

func TestPasswordWrapRoundtrip(t *testing.T) {
	cek := mustCEK(t)
	w, err := crypto.WrapCEKWithPassword(cek, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.UnwrapCEKWithPassword(w, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if got != cek {
		t.Fatal("unwrapped CEK differs")
	}
}

func TestPasswordWrapRejectsWrongPassword(t *testing.T) {
	w, err := crypto.WrapCEKWithPassword(mustCEK(t), "right-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.UnwrapCEKWithPassword(w, "wrong-password"); !errors.Is(err, crypto.ErrWrongCredential) {
		t.Fatalf("want ErrWrongCredential, got %v", err)
	}
}

func TestPasswordWrapRejectsTamperedCiphertext(t *testing.T) {
	w, err := crypto.WrapCEKWithPassword(mustCEK(t), "password-123")
	if err != nil {
		t.Fatal(err)
	}
	w.Sealed[0] ^= 0xFF
	if _, err := crypto.UnwrapCEKWithPassword(w, "password-123"); !errors.Is(err, crypto.ErrWrongCredential) {
		t.Fatalf("want ErrWrongCredential, got %v", err)
	}
}

func TestPasswordWrapsAreUnique(t *testing.T) {
	cek := mustCEK(t)
	a, err := crypto.WrapCEKWithPassword(cek, "same-password")
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypto.WrapCEKWithPassword(cek, "same-password")
	if err != nil {
		t.Fatal(err)
	}
	if a.Salt == b.Salt || a.Nonce == b.Nonce || a.Sealed == b.Sealed {
		t.Fatal("two wraps of the same CEK and password share salt, nonce, or ciphertext")
	}
}

// TestPasswordUnwrapRejectsIterationsOutOfRange confirms a hostile iteration count is
// refused up front rather than driving an unbounded PBKDF2 run.
func TestPasswordUnwrapRejectsIterationsOutOfRange(t *testing.T) {
	w, err := crypto.WrapCEKWithPassword(mustCEK(t), "password-123")
	if err != nil {
		t.Fatal(err)
	}
	for _, iterations := range []uint32{0, crypto.MinPasswordIterations - 1, crypto.MaxPasswordIterations + 1, 1 << 31} {
		w.Iterations = iterations
		_, err := crypto.UnwrapCEKWithPassword(w, "password-123")
		if err == nil || errors.Is(err, crypto.ErrWrongCredential) {
			t.Fatalf("iterations %d: want a range error, got %v", iterations, err)
		}
	}
}

func TestAgeWrapEveryRecipientCanUnwrap(t *testing.T) {
	cek := mustCEK(t)
	ids := []*age.X25519Identity{mustIdentity(t), mustIdentity(t), mustIdentity(t)}
	recipients := make([]age.Recipient, len(ids))
	for i, id := range ids {
		recipients[i] = id.Recipient()
	}
	blob, err := crypto.WrapCEKForAge(cek, recipients)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		got, err := crypto.UnwrapCEKWithAge(blob, []age.Identity{id})
		if err != nil {
			t.Fatalf("recipient %d: %v", i, err)
		}
		if got != cek {
			t.Fatalf("recipient %d: unwrapped CEK differs", i)
		}
	}
}

func TestAgeUnwrapRejectsNonRecipient(t *testing.T) {
	blob, err := crypto.WrapCEKForAge(mustCEK(t), []age.Recipient{mustIdentity(t).Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.UnwrapCEKWithAge(blob, []age.Identity{mustIdentity(t)}); !errors.Is(err, crypto.ErrWrongCredential) {
		t.Fatalf("want ErrWrongCredential, got %v", err)
	}
	if _, err := crypto.UnwrapCEKWithAge(blob, nil); !errors.Is(err, crypto.ErrWrongCredential) {
		t.Fatalf("no identities: want ErrWrongCredential, got %v", err)
	}
}

func TestAgeUnwrapRejectsGarbage(t *testing.T) {
	_, err := crypto.UnwrapCEKWithAge([]byte("not an age file"), []age.Identity{mustIdentity(t)})
	if err == nil || errors.Is(err, crypto.ErrWrongCredential) {
		t.Fatalf("want a parse error, got %v", err)
	}
}

func TestAgeWrapRequiresRecipients(t *testing.T) {
	if _, err := crypto.WrapCEKForAge(mustCEK(t), nil); err == nil {
		t.Fatal("wrapped for zero recipients")
	}
}
