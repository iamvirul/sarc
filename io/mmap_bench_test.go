// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"crypto/rand"
	"os"
	"testing"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// mmapBenchFileSize is well above mmapThreshold so both the mmap and buffered-reader
// paths are exercised on the same real-world regime this optimisation targets.
const mmapBenchFileSize = 128 * 1024 * 1024

func newMmapBenchFile(b *testing.B) *os.File {
	b.Helper()
	f, err := os.CreateTemp("", "sarc-mmap-bench-*.bin")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		f.Close()
		os.Remove(f.Name())
	})

	buf := make([]byte, 4<<20)
	remaining := mmapBenchFileSize
	for remaining > 0 {
		n := len(buf)
		if remaining < n {
			n = remaining
		}
		if _, err := rand.Read(buf[:n]); err != nil {
			b.Fatal(err)
		}
		if _, err := f.Write(buf[:n]); err != nil {
			b.Fatal(err)
		}
		remaining -= n
	}
	return f
}

func mmapBenchFrameBuilder(b *testing.B) (*archive.FrameBuilder, [crypto.KeySize]byte) {
	b.Helper()
	salt, err := crypto.GenerateSalt()
	if err != nil {
		b.Fatal(err)
	}
	key := crypto.NewKeyDeriver("mmap-benchmark-password").DeriveKey(salt)
	fb, err := archive.NewFrameBuilder(key)
	if err != nil {
		b.Fatal(err)
	}
	return fb, key
}

// BenchmarkArchiveIOPath compares the mmap and buffered-reader I/O paths for the same
// large file at the same worker count, isolated from archive-writer overhead: both
// variants read+HMAC+encrypt the file and discard the resulting DataBlocks. This
// isolates exactly the optimisation issue #22 targets (avoiding the buffered read()
// copy) from unrelated archive-format costs.
func BenchmarkArchiveIOPath(b *testing.B) {
	f := newMmapBenchFile(b)
	info, err := f.Stat()
	if err != nil {
		b.Fatal(err)
	}
	size := info.Size()

	discard := func(archive.DataBlock) error { return nil }

	b.Run("mmap", func(b *testing.B) {
		b.SetBytes(size)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			fb, key := mmapBenchFrameBuilder(b)
			mapped, err := newMmappedFile(f, size)
			if err != nil {
				b.Fatalf("mmap unavailable on this platform: %v", err)
			}
			if _, err := encryptAndStreamMmap(mapped.data, fb, key, 4, NopProgressTracker{}, discard); err != nil {
				b.Fatal(err)
			}
			if err := mapped.close(); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("buffered", func(b *testing.B) {
		b.SetBytes(size)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			fb, key := mmapBenchFrameBuilder(b)
			if _, err := f.Seek(0, 0); err != nil {
				b.Fatal(err)
			}
			if _, err := encryptAndStreamParallel(f, fb, key, 4, discard); err != nil {
				b.Fatal(err)
			}
		}
	})
}
