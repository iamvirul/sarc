// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// inlineStreamThreshold is the file size from which ConcurrentArchiver streams a file
// on the writer goroutine (with block-level parallelism) instead of encrypting it whole
// in memory on a worker, so per-file memory stays bounded.
const inlineStreamThreshold = minParallelFileSize

// resultLookahead is how many finished results may wait beyond one per worker. It lets
// workers run ahead while the writer is busy, and bounds memory to
// (workers+resultLookahead) in-memory entries regardless of how many files are archived.
const resultLookahead = 2

// fileJob carries one indexed file path, or a solid group of member paths, to a worker.
// inline jobs are not sent to workers; the writer streams them itself.
type fileJob struct {
	index   int
	path    string
	members []string // non-nil for a solid group job
	inline  bool
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
		return ca.archiveJobs([]fileJob{{index: 0, path: paths[0], inline: true}}, 1)
	}
	return ca.archiveJobs(ca.planJobs(paths), len(paths))
}

// archiveJobs runs jobs through the worker pool and writes their entries in job order
// as they complete. At most workers+resultLookahead results are held at once, so memory
// is bounded by the window, not by the archive size. It stops at the first fatal error.
func (ca *ConcurrentArchiver) archiveJobs(jobs []fileJob, totalFiles int) error {
	results := make([]chan fileResult, len(jobs))
	for i := range results {
		results[i] = make(chan fileResult, 1)
	}
	work := make(chan fileJob)
	slots := make(chan struct{}, ca.workers+resultLookahead)
	done := make(chan struct{})
	defer close(done)

	go func() {
		defer close(work)
		for _, j := range jobs {
			if j.inline {
				continue
			}
			select {
			case slots <- struct{}{}:
			case <-done:
				return
			}
			select {
			case work <- j:
			case <-done:
				return
			}
		}
	}()
	for i := 0; i < ca.workers; i++ {
		go func() {
			for j := range work {
				results[j.index] <- ca.runJob(j)
			}
		}()
	}

	var totalBytes int64
	for _, j := range jobs {
		if j.inline {
			size, err := ca.streamInline(j.path)
			if err != nil {
				return err
			}
			totalBytes += size
			continue
		}
		r := <-results[j.index]
		<-slots
		size, err := ca.writeResult(r)
		if err != nil {
			return err
		}
		totalBytes += size
	}
	if err := ca.w.WriteFooter(); err != nil {
		return fatal(ErrCodeWriteFailed, "write footer", err)
	}
	ca.progress.Done(totalFiles, totalBytes, time.Since(ca.start))
	return nil
}

// streamInline writes a large file straight to the archive with addFileStreaming. A
// recoverable failure is reported to progress and skipped; a fatal one is returned.
func (ca *ConcurrentArchiver) streamInline(path string) (int64, error) {
	info, statErr := os.Stat(path)
	if err := addFileStreaming(ca.w, ca.compression, path, ca.workers, ca.progress); err != nil {
		if isFatal(err) {
			return 0, err
		}
		ca.progress.FileError(path, err)
		return 0, nil
	}
	if statErr != nil {
		return 0, nil
	}
	return info.Size(), nil
}

// writeResult writes one worker result and returns the plaintext bytes it added. A
// recoverable failure is reported to progress and skipped; a fatal one is returned.
func (ca *ConcurrentArchiver) writeResult(r fileResult) (int64, error) {
	if r.err != nil {
		if isFatal(r.err) {
			return 0, r.err
		}
		ca.progress.FileError(r.path, r.err)
		return 0, nil
	}
	if r.members != nil {
		if !r.noEntry {
			if err := ca.w.WriteFileEntry(r.entry); err != nil {
				return 0, fatal(ErrCodeWriteFailed, "write solid entry", err)
			}
		}
		return reportSolidMembers(r.members, ca.progress), nil
	}
	if err := ca.w.WriteFileEntry(r.entry); err != nil {
		return 0, fatal(ErrCodeWriteFailed, "write file entry", err)
	}
	ca.progress.FileFinished(r.name)
	return r.size, nil
}

// planJobs returns one job per path, or, in solid mode, one job per individually stored
// file followed by one job per solid group. Files of at least inlineStreamThreshold
// bytes are marked inline.
func (ca *ConcurrentArchiver) planJobs(paths []string) []fileJob {
	individual := paths
	var groups [][]string
	if ca.compression.solid {
		plan := planSolid(paths)
		individual, groups = plan.individual, plan.groups
	}
	jobs := make([]fileJob, 0, len(individual)+len(groups))
	for _, p := range individual {
		jobs = append(jobs, fileJob{index: len(jobs), path: p, inline: isLargeFile(p)})
	}
	for _, g := range groups {
		jobs = append(jobs, fileJob{index: len(jobs), path: g[0], members: g})
	}
	return jobs
}

// isLargeFile reports whether path is a regular file of at least inlineStreamThreshold
// bytes. Paths that cannot be stat'ed are not large; their error surfaces when archived.
func isLargeFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() >= inlineStreamThreshold
}

// runJob encrypts one worker job: a solid group or a whole file in memory.
func (ca *ConcurrentArchiver) runJob(job fileJob) fileResult {
	if job.members != nil {
		entry, members, err := buildSolidEntry(ca.w, ca.compression, job.members, ca.progress)
		res := fileResult{index: job.index, path: job.path, members: members, err: err, noEntry: entry == nil}
		if entry != nil {
			res.entry = *entry
		}
		return res
	}
	entry, name, size, err := encryptFile(job.path, ca.w, ca.compression, ca.progress)
	return fileResult{index: job.index, path: job.path, entry: entry, name: name, size: size, err: err}
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
