// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// minParallelFileSize is the smallest file size for which intra-file parallel block
// encryption is worth the goroutine/channel setup cost. Below this, files rarely span
// more than a handful of blocks per worker, so the sequential pipeline wins on overhead.
const minParallelFileSize = 4 * 1024 * 1024

// StreamingArchiver archives files one at a time without loading entire files into memory.
// Maximum memory footprint is approximately one chunk (~64 KB) per file at any point.
// In solid mode, small files are buffered by path and written as solid groups when the
// next one would overflow a group, and at Finalize.
type StreamingArchiver struct {
	w           *archive.ArchiveWriter
	compression *compressionPolicy
	progress    ProgressTracker
	start       time.Time
	pending     []inputFile // solid group members not yet written
	pendingSize int         // estimated record stream size of pending
}

// NewStreamingArchiver returns a StreamingArchiver writing to w, openable with password
// (empty for none) and any recipients added with WithAgeRecipients; at least one is
// required. Compression defaults to CompressionAuto at level 3; override with WithCompression.
func NewStreamingArchiver(w io.Writer, password string, progress ProgressTracker, opts ...ArchiverOption) (*StreamingArchiver, error) {
	aw, compression, err := openArchiveWriter(w, password, opts)
	if err != nil {
		return nil, err
	}
	if progress == nil {
		progress = NopProgressTracker{}
	}
	return &StreamingArchiver{w: aw, compression: compression, progress: progress, start: time.Now()}, nil
}

// AddFile reads path from disk and appends it to the archive as a single file entry.
// Plaintext is read from disk, HMAC'd, and chunked on one goroutine; the AES-256-GCM
// seal for each chunk runs across up to GOMAXPROCS worker goroutines once the file is
// large enough to benefit (see minParallelFileSize), so a single large file saturates
// all available cores instead of just one. Memory footprint stays a small, fixed
// multiple of archive.MaxChunkSize regardless of file size.
//
// In solid mode, a small file is only queued here; read errors for queued files are
// reported through the ProgressTracker when its group is written.
//
// A directory is archived recursively (see expandInputs): recoverable failures of its
// files are reported through the ProgressTracker and only fatal errors are returned.
func (sa *StreamingArchiver) AddFile(path string) error {
	files, skipped := expandInputs([]string{path})
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		if len(skipped) > 0 {
			return skipped[0].err
		}
		return sa.addInput(files[0])
	}
	reportSkipped(skipped, sa.progress)
	for _, in := range files {
		if err := sa.addInput(in); err != nil {
			if isFatal(err) {
				return err
			}
			sa.progress.FileError(in.path, err)
		}
	}
	return nil
}

// addInput archives one file, or queues it for a solid group.
func (sa *StreamingArchiver) addInput(in inputFile) error {
	if sa.compression.solid {
		if record, ok := solidCandidate(in); ok {
			if sa.pendingSize+record > archive.MaxSolidStreamSize {
				if err := sa.flushSolid(); err != nil {
					return err
				}
			}
			sa.pending = append(sa.pending, in)
			sa.pendingSize += record
			return nil
		}
	}
	return addFileStreaming(sa.w, sa.compression, in, runtime.GOMAXPROCS(0), sa.progress)
}

// flushSolid writes the queued solid members: as one solid group, or as an individual
// entry when only one is queued.
func (sa *StreamingArchiver) flushSolid() error {
	pending := sa.pending
	sa.pending, sa.pendingSize = nil, 0
	switch len(pending) {
	case 0:
		return nil
	case 1:
		err := addFileStreaming(sa.w, sa.compression, pending[0], runtime.GOMAXPROCS(0), sa.progress)
		if err != nil && !isFatal(err) {
			sa.progress.FileError(pending[0].path, err)
			return nil
		}
		return err
	}
	entry, members, err := buildSolidEntry(sa.w, sa.compression, pending, sa.progress)
	if err != nil {
		return err
	}
	if entry != nil {
		if err := sa.w.WriteFileEntry(*entry); err != nil {
			return fatal(ErrCodeWriteFailed, "write solid entry", err)
		}
	}
	reportSolidMembers(members, sa.progress)
	return nil
}

// addFileStreaming streams in into aw as one file entry, encrypting chunks across
// `workers` goroutines when the file is large enough to benefit (see minParallelFileSize).
// Shared by StreamingArchiver and ConcurrentArchiver's single-file fast path.
func addFileStreaming(aw *archive.ArchiveWriter, compression *compressionPolicy, in inputFile, workers int, progress ProgressTracker) error {
	f, err := os.Open(in.path)
	if err != nil {
		return recoverable(ErrCodeReadFailed, "open file", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return recoverable(ErrCodeReadFailed, "stat file", err)
	}

	progress.FileStarted(in.name, info.Size())

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fatal(ErrCodeWriteFailed, "generate file salt", err)
	}
	fileKey, err := aw.DeriveFileKey(salt)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "derive file key", err)
	}

	probe, err := readProbe(f, info.Size(), compression.mode)
	if err != nil {
		return recoverable(ErrCodeReadFailed, "read compression probe", err)
	}
	codec := compression.codecFor(in.name, probe)

	fb, err := compression.newFrameBuilder(fileKey, codec)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "init frame builder", err)
	}

	frameHdr, err := fb.FrameHeader()
	if err != nil {
		return fatal(ErrCodeWriteFailed, "frame header", err)
	}

	mm, err := archive.NewMetadataManager(fileKey)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "init metadata manager", err)
	}

	encFilename, err := encryptFilename(in.name, fileKey)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "encrypt filename", err)
	}

	pm := archive.PlaintextMetadata{
		EncryptedFilename: encFilename,
		SizeBucket:        archive.BucketizeSize(info.Size()),
		TimestampHash:     archive.HashTimestamp(salt, info.ModTime()),
		Permissions:       uint32(info.Mode().Perm()),
		Codec:             codec,
	}
	metaBlock, err := mm.Seal(pm)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "seal metadata", err)
	}

	interPad, err := fb.InterBlockPadding()
	if err != nil {
		return fatal(ErrCodeWriteFailed, "inter-block padding", err)
	}

	if err := aw.BeginFileEntry(archive.EntryTypeFile, salt, frameHdr, metaBlock, interPad); err != nil {
		return fatal(ErrCodeWriteFailed, "begin file entry", err)
	}

	if workers < 1 {
		workers = 1
	}
	if info.Size() < minParallelFileSize {
		workers = 1
	}

	send := func(db archive.DataBlock) error {
		return aw.AppendDataBlock(db)
	}

	var plaintextHMAC [crypto.HMACSize]byte
	var plaintextSize int64
	if mapped, mmapErr := tryMmap(f, info.Size()); mmapErr == nil {
		// mmap succeeded: encrypt straight out of the mapped page-cache pages,
		// skipping the buffered-reader copy entirely.
		plaintextSize = int64(len(mapped.data))
		plaintextHMAC, err = encryptAndStreamMmap(mapped.data, fb, fileKey, workers, progress, send)
		closeErr := mapped.close()
		if err == nil {
			err = closeErr
		}
	} else {
		// mmap unavailable (small file, unsupported platform, or a syscall failure):
		// fall back to the buffered reader, which is always correct.
		tracked := &progressReader{r: f, progress: progress}
		if workers > 1 {
			plaintextHMAC, err = encryptAndStreamParallel(tracked, fb, fileKey, workers, send)
		} else {
			plaintextHMAC, err = encryptAndStream(tracked, fb, fileKey, send)
		}
		plaintextSize = tracked.total
	}
	if err != nil {
		return fatal(ErrCodeWriteFailed, "encrypt stream", err)
	}

	trailer, err := fb.BuildTrailer(plaintextHMAC, uint64(plaintextSize))
	if err != nil {
		return fatal(ErrCodeWriteFailed, "build trailer", err)
	}

	if err := aw.EndFileEntry(trailer); err != nil {
		return fatal(ErrCodeWriteFailed, "end file entry", err)
	}

	progress.FileFinished(in.name)
	return nil
}

// Finalize writes any queued solid group and the archive footer. Must be called after
// all AddFile calls.
func (sa *StreamingArchiver) Finalize(totalFiles int, totalBytes int64) error {
	if err := sa.flushSolid(); err != nil {
		return err
	}
	if err := sa.w.WriteFooter(); err != nil {
		return fatal(ErrCodeWriteFailed, "write footer", err)
	}
	sa.progress.Done(totalFiles, totalBytes, time.Since(sa.start))
	return nil
}

// progressReader wraps an io.Reader, reports bytes read to a ProgressTracker, and
// counts the total read. It is not safe for concurrent use.
type progressReader struct {
	r        io.Reader
	progress ProgressTracker
	total    int64
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	if n > 0 {
		pr.total += int64(n)
		pr.progress.BytesProcessed(int64(n))
	}
	return n, err
}

// readProbe returns up to compressionProbeSize leading bytes of f for the compression
// decision, using ReadAt so the sequential read position is untouched. It reads nothing
// when mode never probes.
func readProbe(f *os.File, size int64, mode CompressionMode) ([]byte, error) {
	if mode != CompressionAuto || size == 0 {
		return nil, nil
	}
	probe := make([]byte, min(size, compressionProbeSize))
	n, err := f.ReadAt(probe, 0)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return probe[:n], nil
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
