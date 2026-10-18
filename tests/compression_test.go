// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/iamvirul/sarc/archive"
	sarcio "github.com/iamvirul/sarc/io"
)

const compressionTestPassword = "compression-test-password"

// compressibleText returns n bytes of log-like text that zstd shrinks well.
func compressibleText(n int) []byte {
	var buf bytes.Buffer
	for i := 0; buf.Len() < n; i++ {
		fmt.Fprintf(&buf, "2026-10-18T12:%02d:%02dZ level=info service=api msg=\"request completed\" status=200 duration_ms=%d\n", i%60, i%60, i%977)
	}
	return buf.Bytes()[:n]
}

func randomContent(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

type compressionFixture struct {
	name    string
	content []byte
	// autoCodec is the codec CompressionAuto is expected to pick.
	autoCodec archive.Codec
}

// compressionFixtures spans every encrypt path: >= 4 MB text uses the parallel block
// pipeline, smaller files the sequential one, and multi-file ConcurrentArchiver runs
// use the in-memory path.
func compressionFixtures(t *testing.T) []compressionFixture {
	return []compressionFixture{
		{"large.log", compressibleText(6*1024*1024 + 4321), archive.CodecZstd},
		{"medium.json", compressibleText(300*1024 + 17), archive.CodecZstd},
		{"random.bin", randomContent(t, 1024*1024+3), archive.CodecNone},
		{"empty.txt", nil, archive.CodecNone},
	}
}

func writeFixtures(t *testing.T, dir string, fixtures []compressionFixture) []string {
	t.Helper()
	paths := make([]string, len(fixtures))
	for i, f := range fixtures {
		paths[i] = filepath.Join(dir, f.name)
		if err := os.WriteFile(paths[i], f.content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return paths
}

type archiveFunc func(t *testing.T, paths []string, opts sarcio.CompressionOptions) []byte

func archiveStreaming(t *testing.T, paths []string, opts sarcio.CompressionOptions) []byte {
	t.Helper()
	var buf bytes.Buffer
	sa, err := sarcio.NewStreamingArchiver(&buf, compressionTestPassword, nil, sarcio.WithCompression(opts))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if err := sa.AddFile(p); err != nil {
			t.Fatalf("add %s: %v", p, err)
		}
	}
	if err := sa.Finalize(len(paths), 0); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func archiveConcurrent(t *testing.T, paths []string, opts sarcio.CompressionOptions) []byte {
	t.Helper()
	var buf bytes.Buffer
	ca, err := sarcio.NewConcurrentArchiver(&buf, compressionTestPassword, 4, nil, sarcio.WithCompression(opts))
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Archive(paths); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func expectedCodec(mode sarcio.CompressionMode, f compressionFixture) archive.Codec {
	switch mode {
	case sarcio.CompressionAlways:
		return archive.CodecZstd
	case sarcio.CompressionNever:
		return archive.CodecNone
	default:
		return f.autoCodec
	}
}

func listByName(t *testing.T, data []byte) map[string]sarcio.ListResult {
	t.Helper()
	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), compressionTestPassword, nil).List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byName := make(map[string]sarcio.ListResult, len(results))
	for _, r := range results {
		if r.Err != nil {
			t.Fatalf("list entry error: %v", r.Err)
		}
		byName[r.Filename] = r
	}
	return byName
}

func TestCompressionRoundtripAcrossModesAndArchivers(t *testing.T) {
	dir := t.TempDir()
	fixtures := compressionFixtures(t)
	paths := writeFixtures(t, dir, fixtures)

	archivers := map[string]archiveFunc{"streaming": archiveStreaming, "concurrent": archiveConcurrent}
	modes := []sarcio.CompressionMode{sarcio.CompressionAuto, sarcio.CompressionAlways, sarcio.CompressionNever}

	for archiverName, archiveFn := range archivers {
		for _, mode := range modes {
			t.Run(archiverName+"/"+mode.String(), func(t *testing.T) {
				opts := sarcio.CompressionOptions{Mode: mode, Level: archive.DefaultCompressionLevel}
				data := archiveFn(t, paths, opts)

				outDir := t.TempDir()
				results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), compressionTestPassword, nil).Extract(outDir)
				if err != nil {
					t.Fatalf("extract: %v", err)
				}
				if len(results) != len(fixtures) {
					t.Fatalf("got %d results, want %d", len(results), len(fixtures))
				}
				for _, r := range results {
					if !r.OK {
						t.Fatalf("%s failed: %v", r.Filename, r.Err)
					}
				}

				listed := listByName(t, data)
				for _, f := range fixtures {
					got, err := os.ReadFile(filepath.Join(outDir, f.name))
					if err != nil {
						t.Fatal(err)
					}
					if sha256.Sum256(got) != sha256.Sum256(f.content) {
						t.Fatalf("%s: content mismatch after roundtrip", f.name)
					}
					entry := listed[f.name]
					if want := expectedCodec(mode, f).String(); entry.Codec != want {
						t.Fatalf("%s: codec %q, want %q", f.name, entry.Codec, want)
					}
					if entry.OriginalBytes != int64(len(f.content)) {
						t.Fatalf("%s: listed original size %d, want %d", f.name, entry.OriginalBytes, len(f.content))
					}
					if entry.Codec == archive.CodecNone.String() && entry.StoredBytes != entry.OriginalBytes {
						t.Fatalf("%s: uncompressed entry stored %d of %d bytes", f.name, entry.StoredBytes, entry.OriginalBytes)
					}
				}
			})
		}
	}
}

func TestCompressionShrinksCompressibleArchive(t *testing.T) {
	src := filepath.Join(t.TempDir(), "app.log")
	content := compressibleText(2 * 1024 * 1024)
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}
	compressed := archiveStreaming(t, []string{src}, sarcio.DefaultCompressionOptions())
	uncompressed := archiveStreaming(t, []string{src}, sarcio.CompressionOptions{Mode: sarcio.CompressionNever})

	if len(compressed)*5 > len(uncompressed) {
		t.Fatalf("compressed archive %d bytes, want at least 5x smaller than uncompressed %d", len(compressed), len(uncompressed))
	}
	entry := listByName(t, compressed)["app.log"]
	if entry.StoredBytes*5 > entry.OriginalBytes {
		t.Fatalf("listed stored %d of %d bytes, want at least 5x smaller", entry.StoredBytes, entry.OriginalBytes)
	}
}

// maxPaddingSpread bounds how much two archives of the same input can differ in size
// from random per-entry padding alone (inter-block 256-1024 B, trailer 512-2048 B).
const maxPaddingSpread = 4096

func TestAutoCompressionNoSizeRegressionForIncompressibleData(t *testing.T) {
	dir := t.TempDir()
	srcs := map[string][]byte{
		"random.bin": randomContent(t, 2*1024*1024),
		"photo.jpg":  randomContent(t, 512*1024),
	}
	for name, content := range srcs {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		auto := archiveStreaming(t, []string{path}, sarcio.DefaultCompressionOptions())
		never := archiveStreaming(t, []string{path}, sarcio.CompressionOptions{Mode: sarcio.CompressionNever})
		if len(auto) > len(never)+maxPaddingSpread {
			t.Fatalf("%s: auto archive %d bytes, uncompressed %d: size regression", name, len(auto), len(never))
		}
		if codec := listByName(t, auto)[name].Codec; codec != archive.CodecNone.String() {
			t.Fatalf("%s: auto chose codec %q for incompressible data", name, codec)
		}
	}
}

func TestAutoCompressionSkipsCompressedFormatsByExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "looks-compressible.png")
	if err := os.WriteFile(path, compressibleText(256*1024), 0o644); err != nil {
		t.Fatal(err)
	}
	auto := archiveStreaming(t, []string{path}, sarcio.DefaultCompressionOptions())
	if codec := listByName(t, auto)["looks-compressible.png"].Codec; codec != archive.CodecNone.String() {
		t.Fatalf("auto compressed a .png: codec %q", codec)
	}
	always := archiveStreaming(t, []string{path}, sarcio.CompressionOptions{Mode: sarcio.CompressionAlways, Level: 3})
	if codec := listByName(t, always)["looks-compressible.png"].Codec; codec != archive.CodecZstd.String() {
		t.Fatalf("always mode skipped a .png: codec %q", codec)
	}
}

func TestCompressionLevelExtremesRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "levels.txt")
	content := compressibleText(700 * 1024)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, level := range []int{archive.MinCompressionLevel, archive.MaxCompressionLevel} {
		data := archiveStreaming(t, []string{path}, sarcio.CompressionOptions{Mode: sarcio.CompressionAlways, Level: level})
		outDir := t.TempDir()
		results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), compressionTestPassword, nil).Extract(outDir)
		if err != nil || len(results) != 1 || !results[0].OK {
			t.Fatalf("level %d: extract failed: %v %+v", level, err, results)
		}
		got, err := os.ReadFile(filepath.Join(outDir, "levels.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, content) {
			t.Fatalf("level %d: content mismatch", level)
		}
	}
}

func TestListVersion1ArchiveReportsUncompressed(t *testing.T) {
	results, err := sarcio.NewSafeExtractor(bytes.NewReader(readV1Fixture(t)), v1FixturePassword, nil).List()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Codec != archive.CodecNone.String() || r.StoredBytes != r.OriginalBytes {
			t.Fatalf("%s: v1 entry listed as codec %q, %d of %d bytes", r.Filename, r.Codec, r.StoredBytes, r.OriginalBytes)
		}
	}
}
