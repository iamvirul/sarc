// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/iamvirul/sarc/crypto"
)

// encryptAll encrypts plaintext into variable-size blocks using em, for feeding into
// decryptBlocksParallel via a blockReader.
func encryptAllForTest(t *testing.T, em *crypto.EncryptionManager, plaintext []byte, chunkSize int) []crypto.EncryptedBlock {
	t.Helper()
	var blocks []crypto.EncryptedBlock
	for i := 0; i < len(plaintext); i += chunkSize {
		end := i + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		b, err := em.EncryptBlock(plaintext[i:end])
		if err != nil {
			t.Fatalf("encrypt block: %v", err)
		}
		blocks = append(blocks, b)
	}
	return blocks
}

func blockReaderFromSlice(blocks []crypto.EncryptedBlock) blockReader {
	i := 0
	return func() ([crypto.NonceSize]byte, []byte, bool, error) {
		if i >= len(blocks) {
			return [crypto.NonceSize]byte{}, nil, false, nil
		}
		b := blocks[i]
		i++
		return b.Nonce, b.Ciphertext, true, nil
	}
}

// TestDecryptBlocksParallelMatchesSequential verifies the parallel decrypt path
// produces identical plaintext to the sequential path, across worker counts.
func TestDecryptBlocksParallelMatchesSequential(t *testing.T) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	key := crypto.NewKeyDeriver("decrypt-pipeline-test").DeriveKey(salt)
	em, err := crypto.NewEncryptionManager(key)
	if err != nil {
		t.Fatalf("new encryption manager: %v", err)
	}

	plaintext := make([]byte, 3*1024*1024+513)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("generate plaintext: %v", err)
	}
	blocks := encryptAllForTest(t, em, plaintext, 200*1024)

	for _, workers := range []int{1, 2, 3, 4, 8} {
		got, err := collectBlocks(em, workers, blockReaderFromSlice(blocks))
		if err != nil {
			t.Fatalf("workers=%d: decryptBlocksParallel: %v", workers, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("workers=%d: plaintext mismatch after parallel decrypt", workers)
		}
	}
}

// TestDecryptBlocksParallelAuthFailure verifies a tampered block is rejected rather
// than silently producing corrupt plaintext, and that the pipeline terminates cleanly.
func TestDecryptBlocksParallelAuthFailure(t *testing.T) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	key := crypto.NewKeyDeriver("decrypt-pipeline-tamper-test").DeriveKey(salt)
	em, err := crypto.NewEncryptionManager(key)
	if err != nil {
		t.Fatalf("new encryption manager: %v", err)
	}

	plaintext := make([]byte, 2*1024*1024)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("generate plaintext: %v", err)
	}
	blocks := encryptAllForTest(t, em, plaintext, 200*1024)
	blocks[3].Ciphertext[0] ^= 0xFF

	if _, err := collectBlocks(em, 4, blockReaderFromSlice(blocks)); err == nil {
		t.Fatal("expected authentication error on tampered block, got nil")
	}
}

// TestDecryptBlocksParallelReadError verifies a stream-read error from next() surfaces
// as an error rather than hanging.
func TestDecryptBlocksParallelReadError(t *testing.T) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	key := crypto.NewKeyDeriver("decrypt-pipeline-read-error").DeriveKey(salt)
	em, err := crypto.NewEncryptionManager(key)
	if err != nil {
		t.Fatalf("new encryption manager: %v", err)
	}

	wantErr := errors.New("simulated truncated stream")
	next := func() ([crypto.NonceSize]byte, []byte, bool, error) {
		return [crypto.NonceSize]byte{}, nil, false, wantErr
	}

	if _, err := collectBlocks(em, 4, next); !errors.Is(err, wantErr) {
		t.Fatalf("expected wantErr, got %v", err)
	}
}

// TestDecryptBlocksParallelFallsBackSequential verifies workers<2 delegates to the
// sequential path.
func TestDecryptBlocksParallelFallsBackSequential(t *testing.T) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	key := crypto.NewKeyDeriver("decrypt-pipeline-sequential").DeriveKey(salt)
	em, err := crypto.NewEncryptionManager(key)
	if err != nil {
		t.Fatalf("new encryption manager: %v", err)
	}

	plaintext := []byte("small plaintext")
	blocks := encryptAllForTest(t, em, plaintext, 64*1024)

	got, err := collectBlocks(em, 1, blockReaderFromSlice(blocks))
	if err != nil {
		t.Fatalf("decryptBlocksParallel: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("plaintext mismatch")
	}
}

// collectBlocks runs decryptBlocksParallel with a sink that copies each block in order.
func collectBlocks(em *crypto.EncryptionManager, workers int, next blockReader) ([]byte, error) {
	var out bytes.Buffer
	err := decryptBlocksParallel(em, workers, next, func(pt []byte) error {
		_, werr := out.Write(pt)
		return werr
	})
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// TestDecryptBlocksParallelSinkErrorStopsOutputAndDrains confirms a failing sink is
// reported as a sinkError, no further blocks are delivered, and every block is still
// consumed so the caller's stream stays aligned.
func TestDecryptBlocksParallelSinkErrorStopsOutputAndDrains(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	key := crypto.NewKeyDeriver("decrypt-pipeline-sink-error").DeriveKey(salt)
	em, err := crypto.NewEncryptionManager(key)
	if err != nil {
		t.Fatal(err)
	}
	var blocks []crypto.EncryptedBlock
	for i := 0; i < 20; i++ {
		b, err := em.EncryptBlock(bytes.Repeat([]byte{byte(i)}, 1024))
		if err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, b)
	}
	for _, workers := range []int{1, 4} {
		consumed, delivered := 0, 0
		reader := blockReaderFromSlice(blocks)
		next := func() ([crypto.NonceSize]byte, []byte, bool, error) {
			n, ct, ok, err := reader()
			if ok {
				consumed++
			}
			return n, ct, ok, err
		}
		diskFull := errors.New("disk full")
		err := decryptBlocksParallel(em, workers, next, func([]byte) error {
			delivered++
			if delivered == 3 {
				return diskFull
			}
			return nil
		})
		var se *sinkError
		if !errors.As(err, &se) || !errors.Is(err, diskFull) {
			t.Fatalf("workers=%d: want sinkError wrapping disk full, got %v", workers, err)
		}
		if delivered != 3 {
			t.Fatalf("workers=%d: sink called %d times after failing on the 3rd", workers, delivered)
		}
		if consumed != len(blocks) {
			t.Fatalf("workers=%d: consumed %d of %d blocks; stream not drained", workers, consumed, len(blocks))
		}
	}
}
