// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
	sarcio "github.com/iamvirul/sarc/io"
)

type solidFixture struct {
	name    string
	content []byte
	perm    os.FileMode
	solid   bool // expected to land in a solid group
}

// solidFixtures mixes many small compressible files, small incompressible and empty
// files, and one file above the solid member limit.
func solidFixtures(t *testing.T) []solidFixture {
	var fixtures []solidFixture
	for i := 0; i < 30; i++ {
		fixtures = append(fixtures, solidFixture{
			name:    fmt.Sprintf("src-%02d.go", i),
			content: compressibleText(2000 + i*311),
			perm:    0o644,
			solid:   true,
		})
	}
	fixtures = append(fixtures,
		solidFixture{name: "photo.jpg", content: randomContent(t, 40*1024), perm: 0o600, solid: true},
		solidFixture{name: "run.sh", content: []byte("#!/bin/sh\necho ok\n"), perm: 0o755, solid: true},
		solidFixture{name: "empty.txt", content: nil, perm: 0o644, solid: true},
		solidFixture{name: "big.log", content: compressibleText(archive.SolidMemberMaxSize + 1), perm: 0o644, solid: false},
	)
	return fixtures
}

func writeSolidFixtures(t *testing.T, dir string, fixtures []solidFixture) []string {
	t.Helper()
	paths := make([]string, len(fixtures))
	for i, f := range fixtures {
		paths[i] = filepath.Join(dir, f.name)
		if err := os.WriteFile(paths[i], f.content, f.perm); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(paths[i], f.perm); err != nil {
			t.Fatal(err)
		}
	}
	return paths
}

func extractAll(t *testing.T, data []byte) (string, []sarcio.ExtractionResult) {
	t.Helper()
	outDir := t.TempDir()
	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), compressionTestPassword, nil).Extract(outDir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	return outDir, results
}

func solidOptions(mode sarcio.CompressionMode) sarcio.CompressionOptions {
	return sarcio.CompressionOptions{Mode: mode, Level: archive.DefaultCompressionLevel, Solid: true}
}

func TestSolidRoundtripBothArchivers(t *testing.T) {
	fixtures := solidFixtures(t)
	paths := writeSolidFixtures(t, t.TempDir(), fixtures)

	for name, archiveFn := range map[string]archiveFunc{"streaming": archiveStreaming, "concurrent": archiveConcurrent} {
		for _, mode := range []sarcio.CompressionMode{sarcio.CompressionAuto, sarcio.CompressionNever} {
			t.Run(name+"/"+mode.String(), func(t *testing.T) {
				data := archiveFn(t, paths, solidOptions(mode))
				outDir, results := extractAll(t, data)
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
					path := filepath.Join(outDir, f.name)
					got, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, f.content) {
						t.Fatalf("%s: content mismatch", f.name)
					}
					info, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode().Perm() != f.perm {
						t.Fatalf("%s: perm %v, want %v", f.name, info.Mode().Perm(), f.perm)
					}
					entry := listed[f.name]
					if entry.Solid != f.solid {
						t.Fatalf("%s: listed solid=%v, want %v", f.name, entry.Solid, f.solid)
					}
					if entry.OriginalBytes != int64(len(f.content)) {
						t.Fatalf("%s: listed original %d, want %d", f.name, entry.OriginalBytes, len(f.content))
					}
				}
			})
		}
	}
}

func TestSolidArchiveIsMuchSmallerForManySmallFiles(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for i := 0; i < 200; i++ {
		p := filepath.Join(dir, fmt.Sprintf("module-%03d.go", i))
		if err := os.WriteFile(p, compressibleText(3000), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	perFile := archiveConcurrent(t, paths, sarcio.DefaultCompressionOptions())
	solid := archiveConcurrent(t, paths, solidOptions(sarcio.CompressionAuto))
	if len(solid)*4 > len(perFile) {
		t.Fatalf("solid archive %d bytes, want at least 4x smaller than per-file %d", len(solid), len(perFile))
	}
}

// writeLargeGroupInputs writes files that together need more than one solid group.
func writeLargeGroupInputs(t *testing.T, dir string) ([]string, map[string][]byte) {
	t.Helper()
	contents := make(map[string][]byte)
	var paths []string
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("chunk-%02d.txt", i)
		content := append(compressibleText(900*1024), byte(i))
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
		contents[name] = content
	}
	return paths, contents
}

func TestSolidMultipleGroupsRoundtrip(t *testing.T) {
	paths, contents := writeLargeGroupInputs(t, t.TempDir())
	for name, archiveFn := range map[string]archiveFunc{"streaming": archiveStreaming, "concurrent": archiveConcurrent} {
		t.Run(name, func(t *testing.T) {
			data := archiveFn(t, paths, solidOptions(sarcio.CompressionAuto))
			outDir, results := extractAll(t, data)
			if len(results) != len(contents) {
				t.Fatalf("got %d results, want %d", len(results), len(contents))
			}
			for _, r := range results {
				if !r.OK {
					t.Fatalf("%s failed: %v", r.Filename, r.Err)
				}
				got, err := os.ReadFile(filepath.Join(outDir, r.Filename))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, contents[r.Filename]) {
					t.Fatalf("%s: content mismatch", r.Filename)
				}
			}
		})
	}
}

// TestTamperedSolidGroupFailsAloneAndLaterGroupsExtract corrupts the first solid group's
// ciphertext: none of its members may be written, and the next group must still extract.
func TestTamperedSolidGroupFailsAloneAndLaterGroupsExtract(t *testing.T) {
	paths, contents := writeLargeGroupInputs(t, t.TempDir())
	data := archiveConcurrent(t, paths, solidOptions(sarcio.CompressionAuto))
	if first := data[archiveHeaderSize(data)]; first != archive.EntryTypeSolid {
		t.Fatalf("first entry type 0x%02x, want a solid group", first)
	}
	data[firstBlockSizeOffset(t, data)+4+100] ^= 0xFF

	outDir, results := extractAll(t, data)
	var failed, ok int
	for _, r := range results {
		if r.OK {
			ok++
			got, err := os.ReadFile(filepath.Join(outDir, r.Filename))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, contents[r.Filename]) {
				t.Fatalf("%s: content mismatch", r.Filename)
			}
			continue
		}
		failed++
		var ae *sarcio.ArchiveError
		if !errors.As(r.Err, &ae) || ae.Code != sarcio.ErrCodeAuthFailed {
			t.Fatalf("want %s for the tampered group, got %v", sarcio.ErrCodeAuthFailed, r.Err)
		}
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if failed != 1 || ok == 0 || ok >= len(contents) || len(entries) != ok {
		t.Fatalf("want one failed group result and the later group extracted; got %d failed, %d ok, %d files on disk", failed, ok, len(entries))
	}
}

func TestSolidWrongPasswordFailsAtHeader(t *testing.T) {
	paths := writeSolidFixtures(t, t.TempDir(), solidFixtures(t))
	data := archiveConcurrent(t, paths, solidOptions(sarcio.CompressionAuto))
	_, err := sarcio.NewSafeExtractor(bytes.NewReader(data), "wrong-password-123", nil).Extract(t.TempDir())
	requireFatal(t, err, sarcio.ErrCodeAuthFailed)
}

// craftSolidArchive seals stream as a single solid group entry with the public archive
// API, so tests can produce authenticated streams no conforming writer would emit.
func craftSolidArchive(t *testing.T, stream []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	aw, err := archive.NewArchiveWriter(&buf, archive.Credentials{Passwords: []string{compressionTestPassword}})
	if err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteHeader(1); err != nil {
		t.Fatal(err)
	}
	entrySalt, _ := crypto.GenerateSalt()
	fileKey, err := aw.DeriveFileKey(entrySalt)
	if err != nil {
		t.Fatal(err)
	}
	bc, err := archive.NewSolidCompressor(archive.DefaultCompressionLevel)
	if err != nil {
		t.Fatal(err)
	}
	payload := bc.Compress(nil, stream)

	fb, err := archive.NewFrameBuilder(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	frameHdr, err := fb.FrameHeader()
	if err != nil {
		t.Fatal(err)
	}
	mm, err := archive.NewMetadataManager(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := mm.Seal(archive.PlaintextMetadata{SizeBucket: archive.BucketHuge, Codec: archive.CodecZstd})
	if err != nil {
		t.Fatal(err)
	}
	pad, err := fb.InterBlockPadding()
	if err != nil {
		t.Fatal(err)
	}
	var blocks []archive.DataBlock
	for off := 0; off < len(payload); {
		n := min(fb.NextChunkSize(), len(payload)-off)
		db, err := fb.EncryptChunk(payload[off : off+n])
		if err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, db)
		off += n
	}
	trailer, err := fb.BuildTrailer(crypto.ComputeHMAC(fileKey, stream), uint64(len(stream)))
	if err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteFileEntry(archive.FileEntry{
		EntryType: archive.EntryTypeSolid, EntrySalt: entrySalt, FrameHdr: frameHdr,
		Metadata: meta, InterBlockPad: pad, DataBlocks: blocks, Trailer: trailer,
	}); err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteFooter(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// rawSolidRecord encodes a solid record without name validation.
func rawSolidRecord(name string, data []byte) []byte {
	var b []byte
	attrs, _ := archive.AppendAttributes(nil, archive.Attributes{Mode: 0o644})
	b = binary.LittleEndian.AppendUint16(b, uint16(len(name)))
	b = append(b, name...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(attrs)))
	b = append(b, attrs...)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(data)))
	return append(b, data...)
}

func requireSolidEntryRejected(t *testing.T, data []byte) {
	t.Helper()
	outDir := filepath.Join(t.TempDir(), "out")
	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), compressionTestPassword, nil).Extract(outDir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	var ae *sarcio.ArchiveError
	if len(results) != 1 || results[0].OK || !errors.As(results[0].Err, &ae) || ae.Code != sarcio.ErrCodeIntegrityFail {
		t.Fatalf("want one %s result, got %+v", sarcio.ErrCodeIntegrityFail, results)
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Fatalf("rejected solid group still created output: %v", err)
	}
}

func TestCraftedSolidArchiveHelperProducesValidArchive(t *testing.T) {
	stream := append(rawSolidRecord("one.txt", []byte("first")), rawSolidRecord("two.txt", []byte("second"))...)
	outDir, results := extractAll(t, craftSolidArchive(t, stream))
	if len(results) != 2 || !results[0].OK || !results[1].OK {
		t.Fatalf("crafted solid archive failed: %+v", results)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "two.txt"))
	if err != nil || string(got) != "second" {
		t.Fatalf("two.txt = %q, %v", got, err)
	}
}

func TestSolidMemberInSubdirectoryExtractsThere(t *testing.T) {
	stream := append(rawSolidRecord("top.txt", []byte("top")), rawSolidRecord("nested/dir/file.txt", []byte("deep"))...)
	outDir, results := extractAll(t, craftSolidArchive(t, stream))
	if len(results) != 2 || !results[0].OK || !results[1].OK {
		t.Fatalf("solid archive with a nested member failed: %+v", results)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "nested", "dir", "file.txt"))
	if err != nil || string(got) != "deep" {
		t.Fatalf("nested member = %q, %v", got, err)
	}
}

// TestSolidDecompressionBombIsRejected seals a group stream one byte over the maximum;
// it authenticates, so only the solid decoder's size bound stops it.
func TestSolidDecompressionBombIsRejected(t *testing.T) {
	requireSolidEntryRejected(t, craftSolidArchive(t, make([]byte, archive.MaxSolidStreamSize+1)))
}

// TestSolidPathTraversalMemberIsRejected seals an authenticated group whose member name
// tries to escape the output directory; the whole group must be refused unwritten.
func TestSolidPathTraversalMemberIsRejected(t *testing.T) {
	for _, name := range []string{"../escape.txt", "..", "/abs.txt", "nested/../../escape.txt", `..\escape.txt`} {
		t.Run(name, func(t *testing.T) {
			stream := append(rawSolidRecord("safe.txt", []byte("ok")), rawSolidRecord(name, []byte("evil"))...)
			requireSolidEntryRejected(t, craftSolidArchive(t, stream))
		})
	}
}
