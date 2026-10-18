// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
	sarcio "github.com/iamvirul/sarc/io"
)

// craftZstdEntryArchive builds a single-entry CodecZstd archive by hand from the public
// archive API, sealing chunk as one data block regardless of its size. It lets tests
// produce authenticated payloads no conforming writer would emit.
func craftZstdEntryArchive(t *testing.T, name string, chunk []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	archiveSalt, _ := crypto.GenerateSalt()
	aw, err := archive.NewArchiveWriter(&buf, compressionTestPassword, archiveSalt)
	if err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteHeader(archive.ArchiveHeader{Magic: archive.Magic, Version: archive.Version, ArchiveSalt: archiveSalt}, 1); err != nil {
		t.Fatal(err)
	}

	entrySalt, _ := crypto.GenerateSalt()
	fileKey, err := aw.DeriveFileKey(entrySalt)
	if err != nil {
		t.Fatal(err)
	}
	bc, err := archive.NewBlockCompressor(archive.DefaultCompressionLevel)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := archive.NewCompressingFrameBuilder(fileKey, bc)
	if err != nil {
		t.Fatal(err)
	}
	frameHdr, err := fb.FrameHeader()
	if err != nil {
		t.Fatal(err)
	}
	em, err := crypto.NewEncryptionManager(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	nameBlock, err := em.EncryptBlock([]byte(name))
	if err != nil {
		t.Fatal(err)
	}
	mm, err := archive.NewMetadataManager(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := mm.Seal(archive.PlaintextMetadata{
		EncryptedFilename: append(nameBlock.Nonce[:], nameBlock.Ciphertext...),
		SizeBucket:        archive.BucketizeSize(int64(len(chunk))),
		Permissions:       0o644,
		Codec:             archive.CodecZstd,
	})
	if err != nil {
		t.Fatal(err)
	}
	pad, err := fb.InterBlockPadding()
	if err != nil {
		t.Fatal(err)
	}
	if err := aw.BeginFileEntry(archive.EntryTypeFile, entrySalt, frameHdr, meta, pad); err != nil {
		t.Fatal(err)
	}
	db, err := fb.EncryptChunk(chunk)
	if err != nil {
		t.Fatal(err)
	}
	if err := aw.AppendDataBlock(db); err != nil {
		t.Fatal(err)
	}
	trailer, err := fb.BuildTrailer(crypto.ComputeHMAC(fileKey, chunk), uint64(len(chunk)))
	if err != nil {
		t.Fatal(err)
	}
	if err := aw.EndFileEntry(trailer); err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteFooter(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func requireEntryError(t *testing.T, data []byte, code string) {
	t.Helper()
	outDir := filepath.Join(t.TempDir(), "out")
	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), compressionTestPassword, nil).Extract(outDir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(results) != 1 || results[0].OK {
		t.Fatalf("want one failed entry, got %+v", results)
	}
	var ae *sarcio.ArchiveError
	if !errors.As(results[0].Err, &ae) || ae.Code != code {
		t.Fatalf("want %s, got %v", code, results[0].Err)
	}
	if entries, _ := os.ReadDir(outDir); len(entries) != 0 {
		t.Fatalf("failed entry still wrote %d file(s)", len(entries))
	}
}

// TestCraftedArchiveHelperProducesValidArchive proves craftZstdEntryArchive is a valid
// writer, so the rejection below is caused by the oversized block alone.
func TestCraftedArchiveHelperProducesValidArchive(t *testing.T) {
	chunk := compressibleText(100 * 1024)
	data := craftZstdEntryArchive(t, "ok.txt", chunk)
	outDir := t.TempDir()
	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), compressionTestPassword, nil).Extract(outDir)
	if err != nil || len(results) != 1 || !results[0].OK {
		t.Fatalf("crafted archive failed to extract: %v %+v", err, results)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "ok.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, chunk) {
		t.Fatal("crafted archive content mismatch")
	}
}

// TestDecompressionBombBlockIsRejected seals a zstd block that decodes to 4x the
// maximum chunk size. It authenticates, so only the decoder size bound stops it.
func TestDecompressionBombBlockIsRejected(t *testing.T) {
	data := craftZstdEntryArchive(t, "bomb.bin", make([]byte, 4*archive.MaxChunkSize))
	requireEntryError(t, data, sarcio.ErrCodeIntegrityFail)
}

// firstBlockSizeOffset returns the offset of the first data block's 4-byte size field
// in a single-entry archive.
func firstBlockSizeOffset(t *testing.T, data []byte) int {
	t.Helper()
	const headerSize = 4 + 2 + crypto.SaltSize + 8 + crypto.NonceSize + crypto.GCMTagSize + archive.ReservedSize
	off := headerSize + 1 + crypto.SaltSize + 32 + crypto.NonceSize
	off += 4 + int(binary.LittleEndian.Uint32(data[off:])) // metadata size + ciphertext
	off += 4 + int(binary.LittleEndian.Uint32(data[off:])) // inter-block padding
	return off + crypto.NonceSize
}

// TestOversizedBlockLengthIsRejectedBeforeAllocation corrupts a block's length field
// to 4 GiB; the extractor must reject it rather than allocate.
func TestOversizedBlockLengthIsRejectedBeforeAllocation(t *testing.T) {
	src := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(src, compressibleText(10*1024), 0o644); err != nil {
		t.Fatal(err)
	}
	data := archiveStreaming(t, []string{src}, sarcio.DefaultCompressionOptions())
	off := firstBlockSizeOffset(t, data)
	if got := binary.LittleEndian.Uint32(data[off:]); got == 0 || got > archive.MaxPayloadSize+crypto.GCMTagSize {
		t.Fatalf("offset calculation wrong: block size field reads %d", got)
	}
	binary.LittleEndian.PutUint32(data[off:], 0xFFFFFFFF)

	// The length prefix is the only way to find the next field, so the stream cannot
	// be resynchronised: both extract and list must stop with a fatal error.
	_, err := sarcio.NewSafeExtractor(bytes.NewReader(data), compressionTestPassword, nil).Extract(t.TempDir())
	requireFatal(t, err, sarcio.ErrCodeIntegrityFail)

	_, err = sarcio.NewSafeExtractor(bytes.NewReader(data), compressionTestPassword, nil).List()
	requireFatal(t, err, sarcio.ErrCodeIntegrityFail)
}

// TestTamperedBlockFailsOnlyItsOwnEntry flips a ciphertext byte inside the first file's
// data block. That entry must fail authentication while the next entry still extracts,
// proving the reader skips the rest of a failed entry instead of losing its place.
func TestTamperedBlockFailsOnlyItsOwnEntry(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a-first.txt")
	second := filepath.Join(dir, "b-second.txt")
	secondContent := compressibleText(50 * 1024)
	if err := os.WriteFile(first, compressibleText(40*1024), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, secondContent, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []sarcio.CompressionMode{sarcio.CompressionAlways, sarcio.CompressionNever} {
		t.Run(mode.String(), func(t *testing.T) {
			data := archiveStreaming(t, []string{first, second}, sarcio.CompressionOptions{Mode: mode, Level: 3})
			data[firstBlockSizeOffset(t, data)+4+10] ^= 0xFF

			outDir := t.TempDir()
			results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), compressionTestPassword, nil).Extract(outDir)
			if err != nil {
				t.Fatalf("extract: %v", err)
			}
			if len(results) != 2 || results[0].OK || !results[1].OK {
				t.Fatalf("want first entry failed and second OK, got %+v", results)
			}
			got, err := os.ReadFile(filepath.Join(outDir, "b-second.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, secondContent) {
				t.Fatal("second entry content mismatch")
			}
		})
	}
}
