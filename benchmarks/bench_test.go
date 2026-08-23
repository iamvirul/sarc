// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package benchmarks_test

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/iamvirul/sarc/crypto"
	sarcio "github.com/iamvirul/sarc/io"
)

const benchPassword = "benchmark-password1"

func BenchmarkEncryptBlock256KB(b *testing.B) {
	salt, _ := crypto.GenerateSalt()
	key := crypto.NewKeyDeriver(benchPassword).DeriveKey(salt)
	em, _ := crypto.NewEncryptionManager(key)
	plaintext := bytes.Repeat([]byte("X"), crypto.BaseBlockSize)

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := em.EncryptBlock(plaintext); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptBlock256KB(b *testing.B) {
	salt, _ := crypto.GenerateSalt()
	key := crypto.NewKeyDeriver(benchPassword).DeriveKey(salt)
	em, _ := crypto.NewEncryptionManager(key)
	plaintext := bytes.Repeat([]byte("Y"), crypto.BaseBlockSize)
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

	tmp, err := os.CreateTemp("", "sarc-bench-*.bin")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		b.Fatal(err)
	}
	tmp.Close()

	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		sa, err := sarcio.NewStreamingArchiver(&out, benchPassword, nil)
		if err != nil {
			b.Fatal(err)
		}
		if err := sa.AddFile(tmp.Name()); err != nil {
			b.Fatal(err)
		}
		if err := sa.Finalize(1, int64(len(content))); err != nil {
			b.Fatal(err)
		}
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
	content := bytes.Repeat([]byte("concurrent benchmark data"), 256*1024)

	var files [4]*os.File
	for i := range files {
		tmp, err := os.CreateTemp("", "sarc-bench-concurrent-*.bin")
		if err != nil {
			b.Fatal(err)
		}
		if _, err := tmp.Write(content); err != nil {
			b.Fatal(err)
		}
		tmp.Close()
		files[i] = tmp
		b.Cleanup(func() { os.Remove(tmp.Name()) })
	}

	paths := make([]string, 4)
	for i, f := range files {
		paths[i] = f.Name()
	}

	b.SetBytes(int64(len(content)) * 4)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		ca, err := sarcio.NewConcurrentArchiver(&out, benchPassword, 4, nil)
		if err != nil {
			b.Fatal(err)
		}
		if err := ca.Archive(paths); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSingleFileArchiveScaling archives one large file at GOMAXPROCS = 1, 2, 4, 8
// to show intra-file block encryption scales with available cores instead of pinning a
// single-file archive to one core regardless of machine size.
func BenchmarkSingleFileArchiveScaling(b *testing.B) {
	const size = 32 * 1024 * 1024
	pattern := []byte("single-file-scaling-benchmark-data")
	content := bytes.Repeat(pattern, size/len(pattern)+1)
	content = content[:size]

	tmp, err := os.CreateTemp("", "sarc-bench-scaling-*.bin")
	if err != nil {
		b.Fatal(err)
	}
	if _, err := tmp.Write(content); err != nil {
		b.Fatal(err)
	}
	tmp.Close()
	b.Cleanup(func() { os.Remove(tmp.Name()) })

	prevGOMAXPROCS := runtime.GOMAXPROCS(0)

	for _, procs := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("GOMAXPROCS=%d", procs), func(b *testing.B) {
			runtime.GOMAXPROCS(procs)
			b.Cleanup(func() { runtime.GOMAXPROCS(prevGOMAXPROCS) })
			b.SetBytes(size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var out bytes.Buffer
				ca, err := sarcio.NewConcurrentArchiver(&out, benchPassword, 0, nil)
				if err != nil {
					b.Fatal(err)
				}
				if err := ca.Archive([]string{tmp.Name()}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
