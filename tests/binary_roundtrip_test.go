// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"

	sarcio "github.com/iamvirul/sarc/io"
)

const binaryRoundtripPassword = "binary-roundtrip-pass"

// roundtripFile archives src with sarc, extracts it, and returns the extracted bytes.
func roundtripFile(t *testing.T, src string) []byte {
	t.Helper()

	var archiveBuf bytes.Buffer
	sa, err := sarcio.NewStreamingArchiver(&archiveBuf, binaryRoundtripPassword, nil)
	if err != nil {
		t.Fatalf("new archiver: %v", err)
	}
	if err := sa.AddFile(src); err != nil {
		t.Fatalf("add file: %v", err)
	}
	info, err := os.Stat(src)
	if err != nil {
		t.Fatalf("stat src: %v", err)
	}
	if err := sa.Finalize(1, info.Size()); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	outDir := t.TempDir()
	ex := sarcio.NewSafeExtractor(bytes.NewReader(archiveBuf.Bytes()), binaryRoundtripPassword, nil)
	results, err := ex.Extract(outDir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(results) != 1 || !results[0].OK {
		var extractErr error
		if len(results) == 1 {
			extractErr = results[0].Err
		}
		t.Fatalf("extraction failed: %v", extractErr)
	}

	extracted, err := os.ReadFile(filepath.Join(outDir, filepath.Base(src)))
	if err != nil {
		t.Fatalf("read extracted: %v", err)
	}
	return extracted
}

// assertByteIdentical fails the test unless original and extracted are SHA-256 identical.
func assertByteIdentical(t *testing.T, original, extracted []byte) {
	t.Helper()
	want := sha256.Sum256(original)
	got := sha256.Sum256(extracted)
	if want != got {
		t.Fatalf("SHA-256 mismatch: original %d bytes (%x), extracted %d bytes (%x)",
			len(original), want, len(extracted), got)
	}
}

// writeTempFile writes data to a new file under t.TempDir() and returns its path.
func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

// buildBinarySTL produces a synthetic binary STL mesh: an 80-byte header, a
// uint32 triangle count, followed by packed float32 normals/vertices and a
// uint16 attribute byte count per triangle (the standard binary STL layout).
func buildBinarySTL(triangleCount int) []byte {
	buf := new(bytes.Buffer)
	buf.Write(bytes.Repeat([]byte{0xAB}, 80))
	binary.Write(buf, binary.LittleEndian, uint32(triangleCount))

	for i := 0; i < triangleCount; i++ {
		vals := [12]float32{
			0, 0, 1,
			float32(i), float32(i) + 1, float32(i) + 2,
			float32(i) + 3, float32(i) + 4, float32(i) + 5,
			float32(i) + 6, float32(i) + 7, float32(i) + 8,
		}
		for _, v := range vals {
			binary.Write(buf, binary.LittleEndian, math.Float32bits(v))
		}
		binary.Write(buf, binary.LittleEndian, uint16(0))
	}
	return buf.Bytes()
}

// buildBinarySTLFile streams a synthetic binary STL mesh directly to path,
// using the same layout as buildBinarySTL, without holding the full file in
// memory. Returns the SHA-256 of the bytes written.
func buildBinarySTLFile(t *testing.T, path string, triangleCount int) [32]byte {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create mesh file: %v", err)
	}
	hasher := sha256.New()
	w := io.MultiWriter(f, hasher)

	if _, err := w.Write(bytes.Repeat([]byte{0xAB}, 80)); err != nil {
		t.Fatalf("write mesh header: %v", err)
	}
	countBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(countBuf, uint32(triangleCount))
	if _, err := w.Write(countBuf); err != nil {
		t.Fatalf("write triangle count: %v", err)
	}

	triBuf := make([]byte, 50)
	for i := 0; i < triangleCount; i++ {
		vals := [12]float32{
			0, 0, 1,
			float32(i), float32(i) + 1, float32(i) + 2,
			float32(i) + 3, float32(i) + 4, float32(i) + 5,
			float32(i) + 6, float32(i) + 7, float32(i) + 8,
		}
		for j, v := range vals {
			binary.LittleEndian.PutUint32(triBuf[j*4:], math.Float32bits(v))
		}
		binary.LittleEndian.PutUint16(triBuf[48:], 0)
		if _, err := w.Write(triBuf); err != nil {
			t.Fatalf("write triangle %d: %v", i, err)
		}
	}

	if err := f.Close(); err != nil {
		t.Fatalf("close mesh file: %v", err)
	}
	var sum [32]byte
	copy(sum[:], hasher.Sum(nil))
	return sum
}

// hashFile computes the SHA-256 of the file at path by streaming it in
// fixed-size chunks, without loading the whole file into memory.
func hashFile(t *testing.T, path string) [32]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s for hashing: %v", path, err)
	}
	defer f.Close()

	hasher := sha256.New()
	buf := make([]byte, 4<<20)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			hasher.Write(buf[:n])
		}
		if rerr != nil {
			break
		}
	}
	var sum [32]byte
	copy(sum[:], hasher.Sum(nil))
	return sum
}

// archiveExtractFile archives src into a sarc container and extracts it back,
// streaming through disk at every stage (no full-file in-memory buffers), and
// returns the path to the extracted file. Suitable for large payloads.
func archiveExtractFile(t *testing.T, src string) string {
	t.Helper()

	archivePath := filepath.Join(t.TempDir(), "archive.sarc")
	archiveFile, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create archive file: %v", err)
	}
	sa, err := sarcio.NewStreamingArchiver(archiveFile, binaryRoundtripPassword, nil)
	if err != nil {
		t.Fatalf("new archiver: %v", err)
	}
	if err := sa.AddFile(src); err != nil {
		t.Fatalf("add file: %v", err)
	}
	info, err := os.Stat(src)
	if err != nil {
		t.Fatalf("stat src: %v", err)
	}
	if err := sa.Finalize(1, info.Size()); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if err := archiveFile.Close(); err != nil {
		t.Fatalf("close archive file: %v", err)
	}

	archiveRead, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("reopen archive file: %v", err)
	}
	defer archiveRead.Close()

	outDir := t.TempDir()
	ex := sarcio.NewSafeExtractor(archiveRead, binaryRoundtripPassword, nil)
	results, err := ex.Extract(outDir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(results) != 1 || !results[0].OK {
		var extractErr error
		if len(results) == 1 {
			extractErr = results[0].Err
		}
		t.Fatalf("extraction failed: %v", extractErr)
	}

	return filepath.Join(outDir, filepath.Base(src))
}

// buildELF produces a minimal valid ELF64 header (little-endian, x86-64)
// followed by a random body standing in for section/program data.
func buildELF(bodySize int) []byte {
	buf := new(bytes.Buffer)

	ident := [16]byte{0x7F, 'E', 'L', 'F', 2, 1, 1, 0}
	buf.Write(ident[:])
	binary.Write(buf, binary.LittleEndian, uint16(2))      // e_type: ET_EXEC
	binary.Write(buf, binary.LittleEndian, uint16(0x3E))   // e_machine: x86-64
	binary.Write(buf, binary.LittleEndian, uint32(1))      // e_version
	binary.Write(buf, binary.LittleEndian, uint64(0x4000)) // e_entry
	binary.Write(buf, binary.LittleEndian, uint64(64))     // e_phoff
	binary.Write(buf, binary.LittleEndian, uint64(0))      // e_shoff
	binary.Write(buf, binary.LittleEndian, uint32(0))      // e_flags
	binary.Write(buf, binary.LittleEndian, uint16(64))     // e_ehsize
	binary.Write(buf, binary.LittleEndian, uint16(56))     // e_phentsize
	binary.Write(buf, binary.LittleEndian, uint16(1))      // e_phnum
	binary.Write(buf, binary.LittleEndian, uint16(0))      // e_shentsize
	binary.Write(buf, binary.LittleEndian, uint16(0))      // e_shnum
	binary.Write(buf, binary.LittleEndian, uint16(0))      // e_shstrndx

	body := make([]byte, bodySize)
	if _, err := rand.Read(body); err != nil {
		panic(err)
	}
	buf.Write(body)
	return buf.Bytes()
}

// buildSyntheticSQLite mimics the layout of a SQLite database file: the
// 100-byte header (with the canonical magic string) followed by fixed-size
// pages, each carrying a CRC32 checksum in its final 4 bytes so any bit flip
// in the page body is detectable.
func buildSyntheticSQLite(pageCount int) []byte {
	const pageSize = 4096
	buf := new(bytes.Buffer)

	header := make([]byte, 100)
	copy(header, []byte("SQLite format 3\x00"))
	binary.BigEndian.PutUint16(header[16:18], uint16(pageSize))
	buf.Write(header)

	page := make([]byte, pageSize)
	for p := 0; p < pageCount; p++ {
		if _, err := rand.Read(page[:pageSize-4]); err != nil {
			panic(err)
		}
		checksum := crc32.ChecksumIEEE(page[:pageSize-4])
		binary.BigEndian.PutUint32(page[pageSize-4:], checksum)
		buf.Write(page)
	}
	return buf.Bytes()
}

// buildValidPNG encodes a real PNG (correct chunk CRCs, valid Huffman/zlib
// stream) via the standard library's image/png encoder.
func buildValidPNG(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8((x * 7) % 256),
				G: uint8((y * 13) % 256),
				B: uint8((x + y) % 256),
				A: 255,
			})
		}
	}
	buf := new(bytes.Buffer)
	if err := png.Encode(buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// buildNestedZip produces a ZIP archive (with its own per-entry CRC32
// checksums) containing a handful of files, to be archived inside a sarc
// container.
func buildNestedZip(t *testing.T) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	entries := map[string][]byte{
		"readme.txt": []byte("nested archive readme"),
		"data.bin":   bytes.Repeat([]byte{0x00, 0xFF, 0x55, 0xAA}, 1024),
	}
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// TestBinaryRoundtrip3DMesh verifies packed float32 mesh data (binary STL
// layout) survives archive + extract byte-for-byte.
func TestBinaryRoundtrip3DMesh(t *testing.T) {
	original := buildBinarySTL(2000)
	src := writeTempFile(t, "mesh.stl", original)
	extracted := roundtripFile(t, src)
	assertByteIdentical(t, original, extracted)
}

// TestBinaryRoundtrip3DMeshLarge verifies a large packed float32 mesh
// (~200 MB binary STL, several million triangles) survives archive +
// extract byte-for-byte. Skipped under -short.
func TestBinaryRoundtrip3DMeshLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large 3D mesh roundtrip test in -short mode")
	}

	const triangleCount = 4_000_000 // ~200 MB (84-byte header + 50 bytes/triangle)

	src := filepath.Join(t.TempDir(), "large_mesh.stl")
	wantSum := buildBinarySTLFile(t, src, triangleCount)

	extractedPath := archiveExtractFile(t, src)
	gotSum := hashFile(t, extractedPath)

	if wantSum != gotSum {
		t.Fatalf("SHA-256 mismatch on large mesh roundtrip: want %x, got %x", wantSum, gotSum)
	}
}

// TestBinaryRoundtripPNG verifies a valid PNG (with correct chunk CRCs)
// survives archive + extract byte-for-byte.
func TestBinaryRoundtripPNG(t *testing.T) {
	original := buildValidPNG(256, 256)
	src := writeTempFile(t, "image.png", original)
	extracted := roundtripFile(t, src)
	assertByteIdentical(t, original, extracted)

	if !bytes.Equal(extracted[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}) {
		t.Fatal("extracted file is missing the PNG signature")
	}
	if _, err := png.Decode(bytes.NewReader(extracted)); err != nil {
		t.Fatalf("extracted PNG failed to decode: %v", err)
	}
}

// TestBinaryRoundtripExecutable verifies an ELF header plus random body
// survives archive + extract byte-for-byte, preserving section alignment
// and entry point fields exactly.
func TestBinaryRoundtripExecutable(t *testing.T) {
	original := buildELF(64 * 1024)
	src := writeTempFile(t, "program.elf", original)
	extracted := roundtripFile(t, src)
	assertByteIdentical(t, original, extracted)

	if !bytes.Equal(extracted[:4], []byte{0x7F, 'E', 'L', 'F'}) {
		t.Fatal("extracted file is missing the ELF magic")
	}
}

// TestBinaryRoundtripNestedArchive verifies a ZIP file (itself carrying
// per-entry integrity checks) survives being archived inside sarc.
func TestBinaryRoundtripNestedArchive(t *testing.T) {
	original := buildNestedZip(t)
	src := writeTempFile(t, "nested.zip", original)
	extracted := roundtripFile(t, src)
	assertByteIdentical(t, original, extracted)

	zr, err := zip.NewReader(bytes.NewReader(extracted), int64(len(extracted)))
	if err != nil {
		t.Fatalf("extracted zip failed to open: %v", err)
	}
	if len(zr.File) != 2 {
		t.Fatalf("expected 2 entries in nested zip, got %d", len(zr.File))
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open nested entry %s: %v", f.Name, err)
		}
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(rc); err != nil {
			t.Fatalf("read nested entry %s: %v", f.Name, err)
		}
		rc.Close()
	}
}

// TestBinaryRoundtripSQLite verifies a synthetic SQLite-shaped file (fixed
// page size, per-page CRC32) survives archive + extract byte-for-byte, so
// page checksums still validate against the extracted bytes.
func TestBinaryRoundtripSQLite(t *testing.T) {
	original := buildSyntheticSQLite(50)
	src := writeTempFile(t, "database.sqlite", original)
	extracted := roundtripFile(t, src)
	assertByteIdentical(t, original, extracted)

	const pageSize = 4096
	header := extracted[:100]
	if string(header[:16]) != "SQLite format 3\x00" {
		t.Fatal("extracted file is missing the SQLite header magic")
	}
	pages := extracted[100:]
	for p := 0; p*pageSize+pageSize <= len(pages); p++ {
		page := pages[p*pageSize : (p+1)*pageSize]
		want := binary.BigEndian.Uint32(page[pageSize-4:])
		got := crc32.ChecksumIEEE(page[:pageSize-4])
		if want != got {
			t.Fatalf("page %d checksum mismatch after roundtrip: want %x, got %x", p, want, got)
		}
	}
}

// TestBinaryRoundtripLargeFile1GB verifies a 1 GB random binary survives
// archive + extract byte-for-byte. Skipped under -short.
func TestBinaryRoundtripLargeFile1GB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1 GB roundtrip test in -short mode")
	}

	const size = 1 << 30
	src := filepath.Join(t.TempDir(), "large.bin")
	f, err := os.Create(src)
	if err != nil {
		t.Fatalf("create large file: %v", err)
	}
	hasher := sha256.New()
	w := io.MultiWriter(f, hasher)
	buf := make([]byte, 4<<20)
	remaining := int64(size)
	for remaining > 0 {
		n := int64(len(buf))
		if remaining < n {
			n = remaining
		}
		if _, err := rand.Read(buf[:n]); err != nil {
			t.Fatalf("generate random data: %v", err)
		}
		if _, err := w.Write(buf[:n]); err != nil {
			t.Fatalf("write large file: %v", err)
		}
		remaining -= n
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close large file: %v", err)
	}
	var wantSum [32]byte
	copy(wantSum[:], hasher.Sum(nil))

	extractedPath := archiveExtractFile(t, src)
	gotSum := hashFile(t, extractedPath)

	if wantSum != gotSum {
		t.Fatalf("SHA-256 mismatch on 1 GB roundtrip: want %x, got %x", wantSum, gotSum)
	}
}
