// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

func testFrameBuilder(t *testing.T) (*archive.FrameBuilder, [crypto.KeySize]byte) {
	t.Helper()
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	key := crypto.NewKeyDeriver("pipeline-test-password").DeriveKey(salt)
	fb, err := archive.NewFrameBuilder(key)
	if err != nil {
		t.Fatalf("new frame builder: %v", err)
	}
	return fb, key
}

// decryptAll decrypts a slice of DataBlocks (in order) under key and returns the
// concatenated plaintext, for verifying encryptAndStreamParallel's output.
func decryptAll(t *testing.T, key [crypto.KeySize]byte, blocks []archive.DataBlock) []byte {
	t.Helper()
	em, err := crypto.NewEncryptionManager(key)
	if err != nil {
		t.Fatalf("new encryption manager: %v", err)
	}
	var out bytes.Buffer
	for i, b := range blocks {
		pt, err := em.DecryptBlock(crypto.EncryptedBlock{Nonce: b.Nonce, Ciphertext: b.Ciphertext})
		if err != nil {
			t.Fatalf("decrypt block %d: %v", i, err)
		}
		out.Write(pt)
	}
	return out.Bytes()
}

// TestEncryptAndStreamParallelMatchesSequential verifies that the parallel pipeline
// produces the same plaintext (once decrypted) and the same HMAC as the sequential
// pipeline for identical input, across a range of worker counts.
func TestEncryptAndStreamParallelMatchesSequential(t *testing.T) {
	plaintext := make([]byte, 3*1024*1024+777) // spans many variable-size blocks
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("generate plaintext: %v", err)
	}
	wantSum := sha256.Sum256(plaintext)

	for _, workers := range []int{1, 2, 3, 4, 8} {
		fb, key := testFrameBuilder(t)
		var blocks []archive.DataBlock
		mac, err := encryptAndStreamParallel(bytes.NewReader(plaintext), fb, key, workers, func(db archive.DataBlock) error {
			blocks = append(blocks, db)
			return nil
		})
		if err != nil {
			t.Fatalf("workers=%d: encryptAndStreamParallel: %v", workers, err)
		}

		got := decryptAll(t, key, blocks)
		gotSum := sha256.Sum256(got)
		if gotSum != wantSum {
			t.Fatalf("workers=%d: decrypted plaintext does not match original", workers)
		}

		wantMAC := crypto.ComputeHMAC(key, plaintext)
		if mac != wantMAC {
			t.Fatalf("workers=%d: HMAC mismatch: got %x want %x", workers, mac, wantMAC)
		}
	}
}

// TestEncryptAndStreamParallelPreservesOrder confirms blocks are delivered to send()
// in original stream order even though workers complete out of order.
func TestEncryptAndStreamParallelPreservesOrder(t *testing.T) {
	plaintext := make([]byte, 2*1024*1024)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("generate plaintext: %v", err)
	}

	fb, key := testFrameBuilder(t)
	var blocks []archive.DataBlock
	if _, err := encryptAndStreamParallel(bytes.NewReader(plaintext), fb, key, 8, func(db archive.DataBlock) error {
		blocks = append(blocks, db)
		return nil
	}); err != nil {
		t.Fatalf("encryptAndStreamParallel: %v", err)
	}

	got := decryptAll(t, key, blocks)
	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted plaintext does not match original in order")
	}
}

// TestEncryptAndStreamParallelSendErrorPropagates verifies that a failing send()
// callback surfaces as an error instead of hanging, and that the pipeline still
// terminates (no goroutine deadlock) under the race detector.
func TestEncryptAndStreamParallelSendErrorPropagates(t *testing.T) {
	plaintext := make([]byte, 4*1024*1024)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("generate plaintext: %v", err)
	}

	fb, key := testFrameBuilder(t)
	wantErr := errors.New("simulated write failure")
	var calls int
	_, err := encryptAndStreamParallel(bytes.NewReader(plaintext), fb, key, 4, func(db archive.DataBlock) error {
		calls++
		if calls == 2 {
			return wantErr
		}
		return nil
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wantErr, got %v", err)
	}
}

// TestEncryptAndStreamParallelFallsBackSequential verifies workers<2 delegates to the
// sequential pipeline rather than spinning up goroutines.
func TestEncryptAndStreamParallelFallsBackSequential(t *testing.T) {
	plaintext := []byte("small plaintext")
	fb, key := testFrameBuilder(t)
	var blocks []archive.DataBlock
	if _, err := encryptAndStreamParallel(bytes.NewReader(plaintext), fb, key, 1, func(db archive.DataBlock) error {
		blocks = append(blocks, db)
		return nil
	}); err != nil {
		t.Fatalf("encryptAndStreamParallel: %v", err)
	}
	got := decryptAll(t, key, blocks)
	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted plaintext does not match original")
	}
}
