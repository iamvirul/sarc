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

// fileJob carries one indexed file path, or a solid group of member paths, to a worker.
type fileJob struct {
	index   int
	path    string
	members []string // non-nil for a solid group job
}

// fileResult carries the encrypted entry back from a worker.
// index preserves submission order so the writer emits entries in order.
// For a solid group, members holds per-file outcomes and noEntry is set when no
// member could be read, so there is nothing to write.
type fileResult struct {
	index   int
	path    string
	entry   archive.FileEntry
	name    string
	size    int64
	err     error
	members []solidMemberResult
	noEntry bool
}

// ConcurrentArchiver encrypts files in parallel using N worker goroutines
// and writes entries to the archive in original submission order.
type ConcurrentArchiver struct {
	w           *archive.ArchiveWriter
	compression *compressionPolicy
	workers     int
	progress    ProgressTracker
	start       time.Time
}

// NewConcurrentArchiver returns a ConcurrentArchiver writing to w, openable with password
// (empty for none) and any recipients added with WithAgeRecipients; at least one is
// required. workers <= 0 defaults to runtime.NumCPU(). Compression defaults to
// CompressionAuto at level 3; override with WithCompression.
func NewConcurrentArchiver(w io.Writer, password string, workers int, progress ProgressTracker, opts ...ArchiverOption) (*ConcurrentArchiver, error) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	aw, compression, err := openArchiveWriter(w, password, opts)
	if err != nil {
		return nil, err
	}
	if progress == nil {
		progress = NopProgressTracker{}
	}
	return &ConcurrentArchiver{w: aw, compression: compression, workers: workers, progress: progress, start: time.Now()}, nil
}

// Archive encrypts all paths concurrently and writes them to the archive in order.
// Returns the first fatal error, if any. Recoverable per-file errors are reported via progress.
//
// A single input file cannot be parallelised across the file-level worker pool below
// (there is only one job), so that case is routed through addFileStreaming instead,
// which parallelises the block-level AES-256-GCM encryption of that one file across
// ca.workers goroutines so it still saturates all available cores.
func (ca *ConcurrentArchiver) Archive(paths []string) error {
	if len(paths) == 1 {
		var size int64
		if err := addFileStreaming(ca.w, ca.compression, paths[0], ca.workers, ca.progress); err != nil {
			ae, ok := err.(*ArchiveError)
			if !ok || ae.IsFatal() {
				return err
			}
			ca.progress.FileError(paths[0], err)
		} else if info, statErr := os.Stat(paths[0]); statErr == nil {
			size = info.Size()
		}
		if err := ca.w.WriteFooter(); err != nil {
			return fatal(ErrCodeWriteFailed, "write footer", err)
		}
		ca.progress.Done(len(paths), size, time.Since(ca.start))
		return nil
	}

	plannedJobs := ca.planJobs(paths)
	jobs := make(chan fileJob, len(plannedJobs))
	results := make(chan fileResult, len(plannedJobs))

	var wg sync.WaitGroup
	for i := 0; i < ca.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ca.runWorker(jobs, results)
		}()
	}
	for _, j := range plannedJobs {
		jobs <- j
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()

	ordered := make([]fileResult, len(plannedJobs))
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
		if r.members != nil {
			if !r.noEntry {
				if err := ca.w.WriteFileEntry(r.entry); err != nil {
					return fatal(ErrCodeWriteFailed, "write solid entry", err)
				}
			}
			totalBytes += reportSolidMembers(r.members, ca.progress)
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

// planJobs returns one job per path, or, in solid mode, one job per individually stored
// file followed by one job per solid group.
func (ca *ConcurrentArchiver) planJobs(paths []string) []fileJob {
	if !ca.compression.solid {
		jobs := make([]fileJob, len(paths))
		for i, p := range paths {
			jobs[i] = fileJob{index: i, path: p}
		}
		return jobs
	}
	plan := planSolid(paths)
	jobs := make([]fileJob, 0, len(plan.individual)+len(plan.groups))
	for _, p := range plan.individual {
		jobs = append(jobs, fileJob{index: len(jobs), path: p})
	}
	for _, g := range plan.groups {
		jobs = append(jobs, fileJob{index: len(jobs), path: g[0], members: g})
	}
	return jobs
}

func (ca *ConcurrentArchiver) runWorker(jobs <-chan fileJob, results chan<- fileResult) {
	for job := range jobs {
		if job.members != nil {
			entry, members, err := buildSolidEntry(ca.w, ca.compression, job.members, ca.progress)
			res := fileResult{index: job.index, path: job.path, members: members, err: err, noEntry: entry == nil}
			if entry != nil {
				res.entry = *entry
			}
			results <- res
			continue
		}
		entry, name, size, err := encryptFile(job.path, ca.w, ca.compression, ca.progress)
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

// encryptFile opens path, compresses and encrypts it per compression, and returns a complete FileEntry.
func encryptFile(path string, aw *archive.ArchiveWriter, compression *compressionPolicy, progress ProgressTracker) (archive.FileEntry, string, int64, error) {
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
	fileKey, err := aw.DeriveFileKey(salt)
	if err != nil {
		return archive.FileEntry{}, path, 0, fatal(ErrCodeWriteFailed, "derive file key", err)
	}

	plaintext, err := io.ReadAll(&progressReader{r: f, progress: progress})
	if err != nil {
		return archive.FileEntry{}, path, 0, recoverable(ErrCodeReadFailed, "read file", err)
	}

	plaintextHMAC := crypto.ComputeHMAC(fileKey, plaintext)
	codec := compression.codecFor(info.Name(), plaintext[:min(len(plaintext), compressionProbeSize)])

	fb, err := compression.newFrameBuilder(fileKey, codec)
	if err != nil {
		return archive.FileEntry{}, path, 0, fatal(ErrCodeWriteFailed, "init frame builder", err)
	}
	frameHdr, err := fb.FrameHeader()
	if err != nil {
		return archive.FileEntry{}, path, 0, fatal(ErrCodeWriteFailed, "frame header", err)
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
		Codec:             codec,
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
	trailer, err := fb.BuildTrailer(plaintextHMAC, uint64(len(plaintext)))
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
