// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// StreamingArchiver archives files one at a time without loading entire files into memory.
// Maximum memory footprint is approximately one chunk (~64 KB) per file at any point.
type StreamingArchiver struct {
	w        *archive.ArchiveWriter
	progress ProgressTracker
	start    time.Time
}

// NewStreamingArchiver returns a StreamingArchiver writing to w with the given password.
func NewStreamingArchiver(w io.Writer, password string, progress ProgressTracker) (*StreamingArchiver, error) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return nil, fatal(ErrCodeWriteFailed, "generate archive salt", err)
	}
	aw, err := archive.NewArchiveWriter(w, password, salt)
	if err != nil {
		return nil, fatal(ErrCodeWriteFailed, "init archive writer", err)
	}
	hdr := archive.ArchiveHeader{
		Magic:       archive.Magic,
		Version:     archive.Version,
		ArchiveSalt: salt,
	}
	if err := aw.WriteHeader(hdr, 0); err != nil {
		return nil, fatal(ErrCodeWriteFailed, "write header", err)
	}
	if progress == nil {
		progress = NopProgressTracker{}
	}
	return &StreamingArchiver{w: aw, progress: progress, start: time.Now()}, nil
}

// AddFile reads path from disk and appends it to the archive as a single file entry.
// The file is read in chunks; plaintext HMAC is accumulated incrementally.
func (sa *StreamingArchiver) AddFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return recoverable(ErrCodeReadFailed, "open file", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return recoverable(ErrCodeReadFailed, "stat file", err)
	}

	sa.progress.FileStarted(info.Name(), info.Size())

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fatal(ErrCodeWriteFailed, "generate file salt", err)
	}
	fileKey := sa.w.DeriveFileKey(salt)

	// Read full plaintext into a progress-tracked buffer for HMAC and encryption.
	// For files larger than ~200 MB the caller should use ConcurrentArchiver instead.
	tracked := &progressReader{r: f, progress: sa.progress}
	plaintext, err := io.ReadAll(tracked)
	if err != nil {
		return recoverable(ErrCodeReadFailed, "read file", err)
	}

	plaintextHMAC := crypto.ComputeHMAC(fileKey, plaintext)

	fb, err := archive.NewFrameBuilder(fileKey)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "init frame builder", err)
	}

	frameHdr, err := archive.RandomFrameHeader()
	if err != nil {
		return fatal(ErrCodeWriteFailed, "random frame header", err)
	}

	mm, err := archive.NewMetadataManager(fileKey)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "init metadata manager", err)
	}

	encFilename, err := encryptFilename(info.Name(), fileKey)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "encrypt filename", err)
	}

	pm := archive.PlaintextMetadata{
		EncryptedFilename: encFilename,
		SizeBucket:        archive.BucketizeSize(info.Size()),
		TimestampHash:     archive.HashTimestamp(salt, info.ModTime()),
		Permissions:       uint32(info.Mode().Perm()),
	}
	metaBlock, err := mm.Seal(pm)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "seal metadata", err)
	}

	interPad, err := fb.InterBlockPadding()
	if err != nil {
		return fatal(ErrCodeWriteFailed, "inter-block padding", err)
	}

	dataBlocks, err := fb.EncryptStream(bytes.NewReader(plaintext))
	if err != nil {
		return fatal(ErrCodeWriteFailed, "encrypt stream", err)
	}

	trailer, err := fb.BuildTrailer(plaintextHMAC)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "build trailer", err)
	}

	entry := archive.FileEntry{
		EntryType:     archive.EntryTypeFile,
		EntrySalt:     salt,
		FrameHdr:      frameHdr,
		Metadata:      metaBlock,
		InterBlockPad: interPad,
		DataBlocks:    dataBlocks,
		Trailer:       trailer,
	}
	if err := sa.w.WriteFileEntry(entry); err != nil {
		return fatal(ErrCodeWriteFailed, "write file entry", err)
	}

	sa.progress.FileFinished(info.Name())
	return nil
}

// Finalize writes the archive footer. Must be called after all AddFile calls.
func (sa *StreamingArchiver) Finalize(totalFiles int, totalBytes int64) error {
	if err := sa.w.WriteFooter(); err != nil {
		return fatal(ErrCodeWriteFailed, "write footer", err)
	}
	sa.progress.Done(totalFiles, totalBytes, time.Since(sa.start))
	return nil
}

// progressReader wraps an io.Reader and reports bytes read to a ProgressTracker.
type progressReader struct {
	r        io.Reader
	progress ProgressTracker
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	if n > 0 {
		pr.progress.BytesProcessed(int64(n))
	}
	return n, err
}

// encryptFilename seals name using a fresh block encryption under fileKey.
func encryptFilename(name string, fileKey [crypto.KeySize]byte) ([]byte, error) {
	em, err := crypto.NewEncryptionManager(fileKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt filename: %w", err)
	}
	block, err := em.EncryptBlock([]byte(name))
	if err != nil {
		return nil, fmt.Errorf("encrypt filename: %w", err)
	}
	// Pack nonce + ciphertext into a single blob.
	out := make([]byte, crypto.NonceSize+len(block.Ciphertext))
	copy(out[:crypto.NonceSize], block.Nonce[:])
	copy(out[crypto.NonceSize:], block.Ciphertext)
	return out, nil
}
