// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/iamvirul/sarc/crypto"
	sarcio "github.com/iamvirul/sarc/io"
)

// TestAuthTagTamperingPreventsExtraction verifies that flipping a byte in the
// archive ciphertext causes extraction to fail rather than return corrupt plaintext.
func TestAuthTagTamperingPreventsExtraction(t *testing.T) {
	dir := t.TempDir()
	content := []byte("secret content that must not leak")
	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	sa, err := sarcio.NewStreamingArchiver(&buf, "securepassword1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.AddFile(src); err != nil {
		t.Fatal(err)
	}
	if err := sa.Finalize(1, 0); err != nil {
		t.Fatal(err)
	}

	corrupted := buf.Bytes()
	// Flip a byte in the metadata ciphertext region. The archive header is 106 bytes,
	// followed by entry type (1), salt (32), frame header (32), metadata nonce (12),
	// metadata size (4). The metadata ciphertext starts at offset 187.
	corrupted[200] ^= 0xFF

	outDir := filepath.Join(dir, "out")
	ex := sarcio.NewSafeExtractor(bytes.NewReader(corrupted), "securepassword1", nil)
	results, _ := ex.Extract(outDir)

	for _, r := range results {
		if r.OK {
			t.Fatal("extraction succeeded on tampered archive: authentication bypass")
		}
	}
}

// TestNonceUniquenessAcrossBlocks encrypts 512 KB of data and confirms that all
// per-block nonces are unique.
func TestNonceUniquenessAcrossBlocks(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	key := crypto.NewKeyDeriver("password123").DeriveKey(salt)
	em, err := crypto.NewEncryptionManager(key)
	if err != nil {
		t.Fatal(err)
	}

	content := bytes.Repeat([]byte("X"), 512*1024)
	blocks, err := em.EncryptStream(bytes.NewReader(content), crypto.NewRandomVarianceGenerator(8192))
	if err != nil {
		t.Fatal(err)
	}

	seen := make(map[[crypto.NonceSize]byte]bool, len(blocks))
	for _, b := range blocks {
		if seen[b.Nonce] {
			t.Fatalf("nonce reuse detected across %d blocks", len(blocks))
		}
		seen[b.Nonce] = true
	}
}

// TestSaltUniquenessAcrossFiles generates 50 salts and confirms none repeat.
func TestSaltUniquenessAcrossFiles(t *testing.T) {
	seen := make(map[[crypto.SaltSize]byte]bool, 50)
	for i := 0; i < 50; i++ {
		salt, err := crypto.GenerateSalt()
		if err != nil {
			t.Fatal(err)
		}
		if seen[salt] {
			t.Fatalf("salt collision at iteration %d", i)
		}
		seen[salt] = true
	}
}

// TestWrongPasswordFailsExtraction confirms that decryption with a wrong password
// returns an auth error rather than corrupt output.
func TestWrongPasswordFailsExtraction(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(src, []byte("private"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	sa, err := sarcio.NewStreamingArchiver(&buf, "correctpassword1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.AddFile(src); err != nil {
		t.Fatal(err)
	}
	if err := sa.Finalize(1, 0); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "out-wrong")
	ex := sarcio.NewSafeExtractor(bytes.NewReader(buf.Bytes()), "wrongpassword!!", nil)
	results, _ := ex.Extract(outDir)

	for _, r := range results {
		if r.OK {
			t.Fatal("wrong password produced a successful extraction")
		}
	}
}
