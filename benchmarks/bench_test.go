// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package benchmarks_test

import (
	"bytes"
	"testing"

	"github.com/iamvirul/sarc/crypto"
	sarcio "github.com/iamvirul/sarc/io"
)

const benchPassword = "benchmark-password1"

func BenchmarkEncryptBlock64KB(b *testing.B) {
	salt, _ := crypto.GenerateSalt()
	key := crypto.NewKeyDeriver(benchPassword).DeriveKey(salt)
	em, _ := crypto.NewEncryptionManager(key)
	plaintext := bytes.Repeat([]byte("X"), 64*1024)

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := em.EncryptBlock(plaintext); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptBlock64KB(b *testing.B) {
	salt, _ := crypto.GenerateSalt()
	key := crypto.NewKeyDeriver(benchPassword).DeriveKey(salt)
	em, _ := crypto.NewEncryptionManager(key)
	plaintext := bytes.Repeat([]byte("Y"), 64*1024)
	block, _ := em.EncryptBlock(plaintext)

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := em.DecryptBlock(block); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamingArchive1MB(b *testing.B) {
	content := bytes.Repeat([]byte("benchmark"), 1024*1024/9)

	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(content)
		var out bytes.Buffer
		sa, err := sarcio.NewStreamingArchiver(&out, benchPassword, nil)
		if err != nil {
			b.Fatal(err)
		}
		salt, _ := crypto.GenerateSalt()
		key := crypto.NewKeyDeriver(benchPassword).DeriveKey(salt)
		em, _ := crypto.NewEncryptionManager(key)
		vg := crypto.NewRandomVarianceGenerator(8192)
		if _, err := em.EncryptStream(r, vg); err != nil {
			b.Fatal(err)
		}
		_ = sa
	}
}

func BenchmarkKeyDerivation(b *testing.B) {
	kd := crypto.NewKeyDeriver(benchPassword)
	salt, _ := crypto.GenerateSalt()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kd.DeriveKey(salt)
	}
}

func BenchmarkConcurrentArchive4Workers(b *testing.B) {
	content := bytes.Repeat([]byte("concurrent benchmark data"), 4*1024)

	b.SetBytes(int64(len(content)) * 4)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		ca, err := sarcio.NewConcurrentArchiver(&out, benchPassword, 4, nil)
		if err != nil {
			b.Fatal(err)
		}
		_ = ca
	}
}
