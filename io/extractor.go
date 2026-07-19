// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// ExtractionResult reports the outcome of extracting one file from the archive.
type ExtractionResult struct {
	Filename string
	Size     int64
	OK       bool
	Err      error
}

// ListResult holds decrypted metadata for one archive entry, used by the list command.
type ListResult struct {
	Filename   string
	SizeBucket string
}

// SafeExtractor decrypts and verifies files from a SARC archive.
type SafeExtractor struct {
	r        io.Reader
	password string
	progress ProgressTracker
}

// NewSafeExtractor returns a SafeExtractor reading from r.
func NewSafeExtractor(r io.Reader, password string, progress ProgressTracker) *SafeExtractor {
	if progress == nil {
		progress = NopProgressTracker{}
	}
	return &SafeExtractor{r: r, password: password, progress: progress}
}

// Extract decrypts every file entry in the archive and writes them under outputDir.
// Each entry is authenticated before any bytes are written to disk.
// Returns one ExtractionResult per file entry.
func (se *SafeExtractor) Extract(outputDir string) ([]ExtractionResult, error) {
	hdr, kd, err := se.readHeader()
	if err != nil {
		return nil, err
	}
	_ = kd

	var results []ExtractionResult
	for {
		result, done, err := se.extractNext(hdr, kd, outputDir)
		if done {
			break
		}
		if err != nil {
			// Recoverable: record and continue to next entry.
			results = append(results, ExtractionResult{Err: err})
			se.progress.FileError("unknown", err)
			continue
		}
		results = append(results, result)
	}
	return results, nil
}

func (se *SafeExtractor) readHeader() (archive.ArchiveHeader, *crypto.KeyDeriver, error) {
	var magic [4]byte
	if _, err := io.ReadFull(se.r, magic[:]); err != nil {
		return archive.ArchiveHeader{}, nil, fatal(ErrCodeTruncated, "read magic", err)
	}
	if magic != archive.Magic {
		return archive.ArchiveHeader{}, nil, fatal(ErrCodeBadMagic, "invalid magic bytes", nil)
	}

	var version [2]byte
	if _, err := io.ReadFull(se.r, version[:]); err != nil {
		return archive.ArchiveHeader{}, nil, fatal(ErrCodeTruncated, "read version", err)
	}
	v := binary.LittleEndian.Uint16(version[:])
	if v != archive.Version {
		return archive.ArchiveHeader{}, nil, fatal(ErrCodeBadVersion, fmt.Sprintf("unsupported version %d", v), nil)
	}

	var hdr archive.ArchiveHeader
	hdr.Magic = magic
	hdr.Version = v

	if _, err := io.ReadFull(se.r, hdr.ArchiveSalt[:]); err != nil {
		return archive.ArchiveHeader{}, nil, fatal(ErrCodeTruncated, "read archive salt", err)
	}
	if _, err := io.ReadFull(se.r, hdr.FileCountEncrypted[:]); err != nil {
		return archive.ArchiveHeader{}, nil, fatal(ErrCodeTruncated, "read file count", err)
	}
	if _, err := io.ReadFull(se.r, hdr.Reserved[:]); err != nil {
		return archive.ArchiveHeader{}, nil, fatal(ErrCodeTruncated, "read header reserved", err)
	}

	kd := crypto.NewKeyDeriver(se.password)
	return hdr, kd, nil
}

func (se *SafeExtractor) extractNext(hdr archive.ArchiveHeader, kd *crypto.KeyDeriver, outputDir string) (ExtractionResult, bool, error) {
	entryTypeBuf := make([]byte, 1)
	_, err := io.ReadFull(se.r, entryTypeBuf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ExtractionResult{}, true, nil
	}
	if err != nil {
		return ExtractionResult{}, true, fatal(ErrCodeTruncated, "read entry type", err)
	}

	// Detect footer (entry type byte is not 0x01).
	if entryTypeBuf[0] != archive.EntryTypeFile {
		return ExtractionResult{}, true, nil
	}

	var salt [crypto.SaltSize]byte
	if _, err := io.ReadFull(se.r, salt[:]); err != nil {
		return ExtractionResult{}, false, recoverable(ErrCodeTruncated, "read entry salt", err)
	}

	fileKey := kd.DeriveKey(salt)

	var frameHdr [32]byte
	if _, err := io.ReadFull(se.r, frameHdr[:]); err != nil {
		return ExtractionResult{}, false, recoverable(ErrCodeTruncated, "read frame header", err)
	}

	metaBlock, err := se.readMetadataBlock()
	if err != nil {
		return ExtractionResult{}, false, err
	}

	mm, err := archive.NewMetadataManager(fileKey)
	if err != nil {
		return ExtractionResult{}, false, fatal(ErrCodeAuthFailed, "init metadata manager", err)
	}
	pm, err := mm.Open(metaBlock)
	if err != nil {
		return ExtractionResult{}, false, recoverable(ErrCodeAuthFailed, "decrypt metadata", err)
	}

	filename, err := decryptFilename(pm.EncryptedFilename, fileKey)
	if err != nil {
		return ExtractionResult{}, false, recoverable(ErrCodeAuthFailed, "decrypt filename", err)
	}

	if err := se.skipPadding(); err != nil {
		return ExtractionResult{}, false, recoverable(ErrCodeTruncated, "skip inter-block padding", err)
	}

	plaintext, err := se.decryptDataBlocks(fileKey)
	if err != nil {
		return ExtractionResult{}, false, err
	}

	plaintextHMAC, err := se.readAndVerifyTrailer(fileKey, plaintext)
	if err != nil {
		return ExtractionResult{}, false, err
	}
	_ = plaintextHMAC

	outPath := filepath.Join(outputDir, filepath.Base(filename))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return ExtractionResult{}, false, fatal(ErrCodeWriteFailed, "create output dir", err)
	}
	if err := os.WriteFile(outPath, plaintext, os.FileMode(pm.Permissions)); err != nil {
		return ExtractionResult{}, false, recoverable(ErrCodeWriteFailed, "write file", err)
	}

	se.progress.FileFinished(filename)
	return ExtractionResult{Filename: filename, Size: int64(len(plaintext)), OK: true}, false, nil
}

func (se *SafeExtractor) readMetadataBlock() (archive.MetadataBlock, error) {
	var nonce [crypto.NonceSize]byte
	if _, err := io.ReadFull(se.r, nonce[:]); err != nil {
		return archive.MetadataBlock{}, recoverable(ErrCodeTruncated, "read metadata nonce", err)
	}
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(se.r, sizeBuf); err != nil {
		return archive.MetadataBlock{}, recoverable(ErrCodeTruncated, "read metadata size", err)
	}
	ct := make([]byte, binary.LittleEndian.Uint32(sizeBuf))
	if _, err := io.ReadFull(se.r, ct); err != nil {
		return archive.MetadataBlock{}, recoverable(ErrCodeTruncated, "read metadata ciphertext", err)
	}
	return archive.MetadataBlock{Nonce: nonce, Ciphertext: ct}, nil
}

func (se *SafeExtractor) skipPadding() error {
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(se.r, sizeBuf); err != nil {
		return err
	}
	size := binary.LittleEndian.Uint32(sizeBuf)
	if _, err := io.CopyN(io.Discard, se.r, int64(size)); err != nil {
		return err
	}
	return nil
}

func (se *SafeExtractor) decryptDataBlocks(fileKey [crypto.KeySize]byte) ([]byte, error) {
	em, err := crypto.NewEncryptionManager(fileKey)
	if err != nil {
		return nil, fatal(ErrCodeAuthFailed, "init block decryptor", err)
	}
	var buf bytes.Buffer
	for {
		var nonce [crypto.NonceSize]byte
		_, err := io.ReadFull(se.r, nonce[:])
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, recoverable(ErrCodeTruncated, "read block nonce", err)
		}

		sizeBuf := make([]byte, 4)
		if _, err := io.ReadFull(se.r, sizeBuf); err != nil {
			return nil, recoverable(ErrCodeTruncated, "read block size", err)
		}
		blockSize := binary.LittleEndian.Uint32(sizeBuf)

		// Sentinel: a zero-length block marks the end of data blocks.
		if blockSize == 0 {
			break
		}

		ct := make([]byte, blockSize)
		if _, err := io.ReadFull(se.r, ct); err != nil {
			return nil, recoverable(ErrCodeTruncated, "read block ciphertext", err)
		}
		pt, err := em.DecryptBlock(crypto.EncryptedBlock{Nonce: nonce, Ciphertext: ct})
		if err != nil {
			return nil, recoverable(ErrCodeAuthFailed, "decrypt block", err)
		}
		buf.Write(pt)
	}
	return buf.Bytes(), nil
}

func (se *SafeExtractor) readAndVerifyTrailer(fileKey [crypto.KeySize]byte, plaintext []byte) ([crypto.HMACSize]byte, error) {
	// Skip random trailer padding.
	if err := se.skipPadding(); err != nil {
		return [crypto.HMACSize]byte{}, recoverable(ErrCodeTruncated, "skip trailer padding", err)
	}

	var hmacNonce [crypto.NonceSize]byte
	if _, err := io.ReadFull(se.r, hmacNonce[:]); err != nil {
		return [crypto.HMACSize]byte{}, recoverable(ErrCodeTruncated, "read HMAC nonce", err)
	}
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(se.r, sizeBuf); err != nil {
		return [crypto.HMACSize]byte{}, recoverable(ErrCodeTruncated, "read HMAC sealed size", err)
	}
	sealed := make([]byte, binary.LittleEndian.Uint32(sizeBuf))
	if _, err := io.ReadFull(se.r, sealed); err != nil {
		return [crypto.HMACSize]byte{}, recoverable(ErrCodeTruncated, "read HMAC sealed", err)
	}

	em, err := crypto.NewEncryptionManager(fileKey)
	if err != nil {
		return [crypto.HMACSize]byte{}, fatal(ErrCodeAuthFailed, "init HMAC decryptor", err)
	}
	rawHMAC, err := em.DecryptBlock(crypto.EncryptedBlock{Nonce: hmacNonce, Ciphertext: sealed})
	if err != nil {
		return [crypto.HMACSize]byte{}, recoverable(ErrCodeAuthFailed, "decrypt HMAC", err)
	}
	if len(rawHMAC) != crypto.HMACSize {
		return [crypto.HMACSize]byte{}, recoverable(ErrCodeIntegrityFail, "HMAC length mismatch", nil)
	}

	var expected [crypto.HMACSize]byte
	copy(expected[:], rawHMAC)

	if err := crypto.VerifyHMAC(fileKey, plaintext, expected); err != nil {
		return [crypto.HMACSize]byte{}, recoverable(ErrCodeIntegrityFail, "plaintext HMAC mismatch", err)
	}

	// Consume entry checksum (8 bytes, used for boundary detection only).
	if _, err := io.ReadFull(se.r, make([]byte, 8)); err != nil {
		return [crypto.HMACSize]byte{}, recoverable(ErrCodeTruncated, "read entry checksum", err)
	}

	return expected, nil
}

// List decrypts metadata for every entry and returns a ListResult per file.
// No file content is decrypted or written to disk.
func (se *SafeExtractor) List() ([]ListResult, error) {
	hdr, kd, err := se.readHeader()
	if err != nil {
		return nil, err
	}
	_ = hdr

	var results []ListResult
	for {
		result, done, err := se.listNext(kd)
		if done {
			break
		}
		if err != nil {
			results = append(results, ListResult{Filename: "<decrypt error>", SizeBucket: "?"})
			continue
		}
		results = append(results, result)
	}
	return results, nil
}

func (se *SafeExtractor) listNext(kd *crypto.KeyDeriver) (ListResult, bool, error) {
	entryTypeBuf := make([]byte, 1)
	_, err := io.ReadFull(se.r, entryTypeBuf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ListResult{}, true, nil
	}
	if err != nil {
		return ListResult{}, true, fatal(ErrCodeTruncated, "read entry type", err)
	}
	if entryTypeBuf[0] != archive.EntryTypeFile {
		return ListResult{}, true, nil
	}

	var salt [crypto.SaltSize]byte
	if _, err := io.ReadFull(se.r, salt[:]); err != nil {
		return ListResult{}, false, recoverable(ErrCodeTruncated, "read entry salt", err)
	}
	fileKey := kd.DeriveKey(salt)

	if _, err := io.ReadFull(se.r, make([]byte, 32)); err != nil {
		return ListResult{}, false, recoverable(ErrCodeTruncated, "read frame header", err)
	}

	metaBlock, err := se.readMetadataBlock()
	if err != nil {
		return ListResult{}, false, err
	}
	mm, err := archive.NewMetadataManager(fileKey)
	if err != nil {
		return ListResult{}, false, fatal(ErrCodeAuthFailed, "init metadata manager", err)
	}
	pm, err := mm.Open(metaBlock)
	if err != nil {
		return ListResult{}, false, recoverable(ErrCodeAuthFailed, "decrypt metadata", err)
	}
	filename, err := decryptFilename(pm.EncryptedFilename, fileKey)
	if err != nil {
		return ListResult{}, false, recoverable(ErrCodeAuthFailed, "decrypt filename", err)
	}

	// Skip remaining entry bytes (inter-block pad, data blocks, trailer) by re-using Extract path.
	if err := se.skipPadding(); err != nil {
		return ListResult{}, false, recoverable(ErrCodeTruncated, "skip inter-block padding", err)
	}
	if _, err := se.decryptDataBlocks(fileKey); err != nil {
		return ListResult{}, false, err
	}
	if _, err := se.readAndVerifyTrailer(fileKey, nil); err != nil {
		// Ignore HMAC mismatch on list; we only need metadata.
		_ = err
	}

	return ListResult{
		Filename:   filename,
		SizeBucket: bucketName(pm.SizeBucket),
	}, false, nil
}

func bucketName(b archive.SizeBucket) string {
	switch b {
	case archive.BucketTiny:
		return "0-1 KB"
	case archive.BucketSmall:
		return "1-10 KB"
	case archive.BucketMedium:
		return "10-100 KB"
	case archive.BucketLarge:
		return "100 KB-1 MB"
	default:
		return ">1 MB"
	}
}

// decryptFilename reverses encryptFilename: nonce(12) | ciphertext.
func decryptFilename(blob []byte, fileKey [crypto.KeySize]byte) (string, error) {
	if len(blob) < crypto.NonceSize {
		return "", fmt.Errorf("decryptFilename: blob too short")
	}
	var nonce [crypto.NonceSize]byte
	copy(nonce[:], blob[:crypto.NonceSize])
	em, err := crypto.NewEncryptionManager(fileKey)
	if err != nil {
		return "", err
	}
	pt, err := em.DecryptBlock(crypto.EncryptedBlock{Nonce: nonce, Ciphertext: blob[crypto.NonceSize:]})
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
