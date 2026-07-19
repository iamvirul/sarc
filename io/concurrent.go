// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// fileJob carries one indexed file path to a worker.
type fileJob struct {
	index int
	path  string
}

// fileResult carries the encrypted entry back from a worker.
// index preserves submission order so the writer emits entries in order.
type fileResult struct {
	index int
	path  string
	entry archive.FileEntry
	name  string
	size  int64
	err   error
}

// ConcurrentArchiver encrypts files in parallel using N worker goroutines
// and writes entries to the archive in original submission order.
type ConcurrentArchiver struct {
	w        *archive.ArchiveWriter
	workers  int
	progress ProgressTracker
	start    time.Time
}

// NewConcurrentArchiver returns a ConcurrentArchiver writing to w.
// workers <= 0 defaults to runtime.NumCPU().
func NewConcurrentArchiver(w io.Writer, password string, workers int, progress ProgressTracker) (*ConcurrentArchiver, error) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
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
	return &ConcurrentArchiver{w: aw, workers: workers, progress: progress, start: time.Now()}, nil
}

// Archive encrypts all paths concurrently and writes them to the archive in order.
// Returns the first fatal error, if any. Recoverable per-file errors are reported via progress.
func (ca *ConcurrentArchiver) Archive(paths []string) error {
	jobs := make(chan fileJob, len(paths))
	results := make(chan fileResult, len(paths))

	var wg sync.WaitGroup
	for i := 0; i < ca.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ca.runWorker(jobs, results)
		}()
	}
	for i, p := range paths {
		jobs <- fileJob{index: i, path: p}
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()

	ordered := make([]fileResult, len(paths))
	for r := range results {
		if r.index < len(ordered) {
			ordered[r.index] = r
		}
	}

	var totalBytes int64
	var firstFatal error
	for _, r := range ordered {
		if r.err != nil {
			ae, ok := r.err.(*ArchiveError)
			if ok && ae.IsFatal() {
				if firstFatal == nil {
					firstFatal = r.err
				}
				continue
			}
			ca.progress.FileError(r.path, r.err)
			continue
		}
		if err := ca.w.WriteFileEntry(r.entry); err != nil {
			return fatal(ErrCodeWriteFailed, "write file entry", err)
		}
		totalBytes += r.size
		ca.progress.FileFinished(r.name)
	}
	if firstFatal != nil {
		return firstFatal
	}
	if err := ca.w.WriteFooter(); err != nil {
		return fatal(ErrCodeWriteFailed, "write footer", err)
	}
	ca.progress.Done(len(paths), totalBytes, time.Since(ca.start))
	return nil
}

func (ca *ConcurrentArchiver) runWorker(jobs <-chan fileJob, results chan<- fileResult) {
	for job := range jobs {
		entry, name, size, err := encryptFile(job.path, ca.w, ca.progress)
		results <- fileResult{
			index: job.index,
			path:  job.path,
			entry: entry,
			name:  name,
			size:  size,
			err:   err,
		}
	}
}

// encryptFile opens path, encrypts it, and returns a complete FileEntry.
func encryptFile(path string, aw *archive.ArchiveWriter, progress ProgressTracker) (archive.FileEntry, string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return archive.FileEntry{}, path, 0, recoverable(ErrCodeReadFailed, "open file", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return archive.FileEntry{}, path, 0, recoverable(ErrCodeReadFailed, "stat file", err)
	}

	progress.FileStarted(info.Name(), info.Size())

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return archive.FileEntry{}, path, 0, fatal(ErrCodeWriteFailed, "generate salt", err)
	}
	fileKey := aw.DeriveFileKey(salt)

	plaintext, err := io.ReadAll(&progressReader{r: f, progress: progress})
	if err != nil {
		return archive.FileEntry{}, path, 0, recoverable(ErrCodeReadFailed, "read file", err)
	}

	plaintextHMAC := crypto.ComputeHMAC(fileKey, plaintext)

	fb, err := archive.NewFrameBuilder(fileKey)
	if err != nil {
		return archive.FileEntry{}, path, 0, fatal(ErrCodeWriteFailed, "init frame builder", err)
	}
	frameHdr, err := archive.RandomFrameHeader()
	if err != nil {
		return archive.FileEntry{}, path, 0, fatal(ErrCodeWriteFailed, "random frame header", err)
	}
	mm, err := archive.NewMetadataManager(fileKey)
	if err != nil {
		return archive.FileEntry{}, path, 0, fatal(ErrCodeWriteFailed, "init metadata manager", err)
	}
	encName, err := encryptFilename(info.Name(), fileKey)
	if err != nil {
		return archive.FileEntry{}, path, 0, fatal(ErrCodeWriteFailed, "encrypt filename", err)
	}

	pm := archive.PlaintextMetadata{
		EncryptedFilename: encName,
		SizeBucket:        archive.BucketizeSize(info.Size()),
		TimestampHash:     archive.HashTimestamp(salt, info.ModTime()),
		Permissions:       uint32(info.Mode().Perm()),
	}
	metaBlock, err := mm.Seal(pm)
	if err != nil {
		return archive.FileEntry{}, path, 0, fatal(ErrCodeWriteFailed, "seal metadata", err)
	}
	interPad, err := fb.InterBlockPadding()
	if err != nil {
		return archive.FileEntry{}, path, 0, fatal(ErrCodeWriteFailed, "inter-block padding", err)
	}
	dataBlocks, err := fb.EncryptStream(bytes.NewReader(plaintext))
	if err != nil {
		return archive.FileEntry{}, path, 0, fatal(ErrCodeWriteFailed, "encrypt stream", err)
	}
	trailer, err := fb.BuildTrailer(plaintextHMAC)
	if err != nil {
		return archive.FileEntry{}, path, 0, fatal(ErrCodeWriteFailed, "build trailer", err)
	}

	return archive.FileEntry{
		EntryType:     archive.EntryTypeFile,
		EntrySalt:     salt,
		FrameHdr:      frameHdr,
		Metadata:      metaBlock,
		InterBlockPad: interPad,
		DataBlocks:    dataBlocks,
		Trailer:       trailer,
	}, info.Name(), info.Size(), nil
}
