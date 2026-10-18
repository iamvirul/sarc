// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package benchmarks_test

import (
	"bytes"
	"crypto/rand"
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

// BenchmarkArchiveSizeTargets times a single-file archive through NewConcurrentArchiver
// (the CLI's default path for `sarc archive <file>`) at each size from issue #24's
// target table, as a permanent, visible regression guard:
//
//	1 KB   < 50ms   1 MB   < 100ms   10 MB  < 500ms   100 MB < 2s
//
// The table's 1 GB / < 10s row is already covered on every PR by the "sarc vs zip"
// workflow (.github/workflows/benchmark.yml), which archives a real 1 GB file with the
// built CLI binary and posts throughput as a PR comment; duplicating that here would
// make the `-benchtime=1x` smoke run (see CLAUDE.md) write and archive an extra 1 GB
// file on every CI run for no new coverage.
//
// Read ns/op from `go test -bench=BenchmarkArchiveSizeTargets -benchtime=Nx` output and
// compare against the target in each sub-benchmark's name; this file intentionally does
// not assert against the targets with b.Fatal, since a hard time-based pass/fail is
// prone to flake on shared/noisy CI runners.
func BenchmarkArchiveSizeTargets(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB_target-50ms", 1024},
		{"1MB_target-100ms", 1024 * 1024},
		{"10MB_target-500ms", 10 * 1024 * 1024},
		{"100MB_target-2s", 100 * 1024 * 1024},
	}

	for _, s := range sizes {
		b.Run(s.name, func(b *testing.B) {
			pattern := []byte("sarc-archive-size-target-benchmark")
			content := bytes.Repeat(pattern, s.size/len(pattern)+1)
			content = content[:s.size]

			tmp, err := os.CreateTemp("", "sarc-bench-target-*.bin")
			if err != nil {
				b.Fatal(err)
			}
			if _, err := tmp.Write(content); err != nil {
				b.Fatal(err)
			}
			tmp.Close()
			b.Cleanup(func() { os.Remove(tmp.Name()) })

			b.SetBytes(int64(s.size))
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

// manySmallFilesCount is the file count for the many-small-files benchmarks (issue #18).
const manySmallFilesCount = 100

// writeManySmallFiles creates manySmallFilesCount 4 KB files in a temp dir and returns their paths.
func writeManySmallFiles(b *testing.B) []string {
	b.Helper()
	dir := b.TempDir()
	content := bytes.Repeat([]byte("many-small-files"), 256)
	paths := make([]string, manySmallFilesCount)
	for i := range paths {
		paths[i] = fmt.Sprintf("%s/small-%03d.bin", dir, i)
		if err := os.WriteFile(paths[i], content, 0o644); err != nil {
			b.Fatal(err)
		}
	}
	return paths
}

// BenchmarkArchiveManySmallFiles archives 100 small files. Run time is dominated by
// key derivation, so it tracks whether PBKDF2 runs once per archive or once per file.
func BenchmarkArchiveManySmallFiles(b *testing.B) {
	paths := writeManySmallFiles(b)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		ca, err := sarcio.NewConcurrentArchiver(&out, benchPassword, 0, nil)
		if err != nil {
			b.Fatal(err)
		}
		if err := ca.Archive(paths); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkExtractManySmallFiles extracts a 100-file archive, the decrypt-side
// counterpart of BenchmarkArchiveManySmallFiles.
func BenchmarkExtractManySmallFiles(b *testing.B) {
	paths := writeManySmallFiles(b)
	var archived bytes.Buffer
	ca, err := sarcio.NewConcurrentArchiver(&archived, benchPassword, 0, nil)
	if err != nil {
		b.Fatal(err)
	}
	if err := ca.Archive(paths); err != nil {
		b.Fatal(err)
	}
	outDir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ex := sarcio.NewSafeExtractor(bytes.NewReader(archived.Bytes()), benchPassword, nil)
		results, err := ex.Extract(outDir)
		if err != nil {
			b.Fatal(err)
		}
		if len(results) != manySmallFilesCount {
			b.Fatalf("extracted %d entries, want %d", len(results), manySmallFilesCount)
		}
	}
}

// compressionBenchSize is the input size for the compression benchmarks.
const compressionBenchSize = 16 * 1024 * 1024

// compressionBenchInputs returns log-like text (compressible) and random bytes
// (incompressible, like JPEG/MP4 payloads) of compressionBenchSize each.
func compressionBenchInputs(b *testing.B) map[string][]byte {
	b.Helper()
	var text bytes.Buffer
	for i := 0; text.Len() < compressionBenchSize; i++ {
		fmt.Fprintf(&text, "2026-10-18T12:%02d:%02dZ level=info service=api msg=\"request completed\" status=%d duration_ms=%d\n",
			i%60, (i/60)%60, 200+(i%7)*50, i%977)
	}
	random := make([]byte, compressionBenchSize)
	if _, err := rand.Read(random); err != nil {
		b.Fatal(err)
	}
	return map[string][]byte{"text": text.Bytes()[:compressionBenchSize], "random": random}
}

// BenchmarkArchiveCompression archives compressible and incompressible inputs with
// compression auto and off, reporting throughput and stored/original ratio. The random
// input with auto vs never shows the cost of the auto-mode probe on data it skips.
func BenchmarkArchiveCompression(b *testing.B) {
	modes := map[string]sarcio.CompressionMode{"auto": sarcio.CompressionAuto, "never": sarcio.CompressionNever}
	for inputName, content := range compressionBenchInputs(b) {
		path := fmt.Sprintf("%s/%s.dat", b.TempDir(), inputName)
		if err := os.WriteFile(path, content, 0o644); err != nil {
			b.Fatal(err)
		}
		for modeName, mode := range modes {
			b.Run(inputName+"/"+modeName, func(b *testing.B) {
				opts := sarcio.WithCompression(sarcio.CompressionOptions{Mode: mode, Level: 3})
				var archived int
				b.SetBytes(int64(len(content)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var out bytes.Buffer
					ca, err := sarcio.NewConcurrentArchiver(&out, benchPassword, 0, nil, opts)
					if err != nil {
						b.Fatal(err)
					}
					if err := ca.Archive([]string{path}); err != nil {
						b.Fatal(err)
					}
					archived = out.Len()
				}
				b.ReportMetric(float64(archived)/float64(len(content)), "ratio")
			})
		}
	}
}

// BenchmarkExtractCompressedText extracts a zstd-compressed 16 MB text archive.
func BenchmarkExtractCompressedText(b *testing.B) {
	content := compressionBenchInputs(b)["text"]
	path := fmt.Sprintf("%s/text.dat", b.TempDir())
	if err := os.WriteFile(path, content, 0o644); err != nil {
		b.Fatal(err)
	}
	var archived bytes.Buffer
	ca, err := sarcio.NewConcurrentArchiver(&archived, benchPassword, 0, nil)
	if err != nil {
		b.Fatal(err)
	}
	if err := ca.Archive([]string{path}); err != nil {
		b.Fatal(err)
	}
	outDir := b.TempDir()

	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := sarcio.NewSafeExtractor(bytes.NewReader(archived.Bytes()), benchPassword, nil).Extract(outDir)
		if err != nil || len(results) != 1 || !results[0].OK {
			b.Fatalf("extract failed: %v %+v", err, results)
		}
	}
}
