// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	stdhmac "crypto/hmac"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// restoreFile is one file being assembled from chunks in a temporary file beside its
// destination.
type restoreFile struct {
	version archive.FileVersion
	outPath string
	tmpPath string
	pending int // chunk positions not yet written
	err     error
}

// chunkTarget is one position in a file that a chunk fills.
type chunkTarget struct {
	file   *restoreFile
	offset int64
}

// extractIncremental restores the newest state of an incremental archive. Each pack
// holding a needed chunk is read once, in archive order, and every chunk is checked
// against its keyed ID before it is written to the positions that use it. A file is
// renamed into place only after all of its chunks are written, so unverified or
// incomplete data never appears under its name.
func (se *SafeExtractor) extractIncremental(keys *archive.KeySchedule, outputDir string) ([]ExtractionResult, error) {
	ia, err := se.openIncremental(keys)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fatal(ErrCodeWriteFailed, "create output dir", err)
	}
	restores, targets := prepareRestore(ia, outputDir)
	defer func() {
		for _, rf := range restores {
			if rf.tmpPath != "" {
				_ = os.Remove(rf.tmpPath)
			}
		}
	}()

	byPack := map[int64][]uint64{}
	for n := range targets {
		loc := ia.chunks[n]
		byPack[loc.packOffset] = append(byPack[loc.packOffset], n)
	}
	packs := make([]int64, 0, len(byPack))
	for p := range byPack {
		packs = append(packs, p)
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i] < packs[j] })

	dec, err := archive.NewChunkDecompressor()
	if err != nil {
		return nil, fatal(ErrCodeReadFailed, "init chunk decompressor", err)
	}
	defer dec.Close()
	idKey, err := keys.ChunkIDKey()
	if err != nil {
		return nil, fatal(ErrCodeAuthFailed, "derive chunk key", err)
	}
	for _, p := range packs {
		needed := byPack[p]
		sort.Slice(needed, func(i, j int) bool { return ia.chunks[needed[i]].offset < ia.chunks[needed[j]].offset })
		if err := se.restorePack(ia, p, needed, targets, dec, idKey); err != nil {
			for _, n := range needed {
				for _, t := range targets[n] {
					if t.file.err == nil {
						t.file.err = err
					}
				}
			}
		}
	}
	return se.publishRestores(restores), nil
}

// prepareRestore creates an empty temporary file for each current file and maps every
// needed chunk to the positions it fills. A file whose name is unsafe or whose
// temporary file cannot be created carries the error instead.
func prepareRestore(ia *incrementalArchive, outputDir string) ([]*restoreFile, map[uint64][]chunkTarget) {
	files := ia.sortedFiles()
	restores := make([]*restoreFile, 0, len(files))
	targets := map[uint64][]chunkTarget{}
	for _, f := range files {
		rf := &restoreFile{version: f, pending: len(f.Chunks)}
		restores = append(restores, rf)
		outPath, err := entryOutputPath(outputDir, f.Name)
		if err != nil {
			rf.err = err
			continue
		}
		tmp, err := os.CreateTemp(filepath.Dir(outPath), tempFilePattern)
		if err != nil {
			rf.err = recoverable(ErrCodeWriteFailed, "create file", err)
			continue
		}
		rf.outPath, rf.tmpPath = outPath, tmp.Name()
		if err := tmp.Close(); err != nil {
			rf.err = recoverable(ErrCodeWriteFailed, "create file", err)
			continue
		}
		var offset int64
		for _, n := range f.Chunks {
			targets[n] = append(targets[n], chunkTarget{file: rf, offset: offset})
			offset += int64(ia.chunks[n].raw)
		}
	}
	return restores, targets
}

// restorePack reads the pack at packOffset and writes each of needed (chunk numbers
// sorted by pack offset) to its targets. It verifies the pack's HMAC and size at the
// end, so any damage to the pack fails the files that use it.
func (se *SafeExtractor) restorePack(ia *incrementalArchive, packOffset int64, needed []uint64, targets map[uint64][]chunkTarget, dec *archive.BlockDecompressor, idKey [crypto.KeySize]byte) error {
	sub, _ := entryReaderAt(se.random, se.randomSize, packOffset)
	var entryType [1]byte
	if _, err := io.ReadFull(sub.r, entryType[:]); err != nil {
		return recoverable(ErrCodeTruncated, "read pack", err)
	}
	if entryType[0] != archive.EntryTypePack {
		return recoverable(ErrCodeIntegrityFail, "expected a pack entry", nil)
	}
	head, err := sub.readEntryHead(ia.keys)
	if err != nil {
		return err
	}
	if err := sub.skipPadding(); err != nil {
		return recoverable(ErrCodeTruncated, "skip pack padding", err)
	}

	mac := stdhmac.New(sha256.New, head.fileKey[:])
	var size uint64
	router := chunkRouter{chunks: ia.chunks, needed: needed, deliver: func(n uint64, stored []byte) error {
		return deliverChunk(ia.chunks[n], stored, targets[n], dec, idKey)
	}}
	err = sub.streamDataBlocks(head.fileKey, archive.BucketHuge, archive.CodecNone, nil, func(pt []byte) error {
		mac.Write(pt)
		size += uint64(len(pt))
		return router.feed(pt)
	})
	if router.err != nil {
		return router.err
	}
	if err != nil {
		return err
	}
	if router.idx != len(needed) {
		return recoverable(ErrCodeIntegrityFail, "pack is shorter than its index", nil)
	}
	trailer, err := sub.readTrailer(head.fileKey, ia.keys.Version())
	if err != nil {
		return err
	}
	if !stdhmac.Equal(mac.Sum(nil), trailer.hmac[:]) || trailer.plaintextSize != size {
		return recoverable(ErrCodeIntegrityFail, "pack HMAC mismatch", nil)
	}
	return nil
}

// deliverChunk decodes one chunk's stored bytes, checks its size and keyed ID, and
// writes it to each target whose file has not failed.
func deliverChunk(loc chunkLocation, stored []byte, targets []chunkTarget, dec *archive.BlockDecompressor, idKey [crypto.KeySize]byte) error {
	raw := stored
	if loc.codec == archive.CodecZstd {
		var err error
		if raw, err = dec.Decompress(stored); err != nil {
			return recoverable(ErrCodeIntegrityFail, "decompress chunk", err)
		}
	}
	id := crypto.ComputeHMAC(idKey, raw)
	if len(raw) != int(loc.raw) || !stdhmac.Equal(id[:], loc.id[:]) {
		return recoverable(ErrCodeIntegrityFail, "chunk failed verification", nil)
	}
	for _, t := range targets {
		if t.file.err != nil {
			continue
		}
		if err := writeAtPath(t.file.tmpPath, raw, t.offset); err != nil {
			t.file.err = recoverable(ErrCodeWriteFailed, "write file", err)
			continue
		}
		t.file.pending--
	}
	return nil
}

// writeAtPath writes data at offset in the file at path. Files are opened per write so
// a restore of many files never holds more than one open.
func writeAtPath(path string, data []byte, offset int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(data, offset); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// publishRestores renames every complete file into place and reports each outcome.
func (se *SafeExtractor) publishRestores(restores []*restoreFile) []ExtractionResult {
	results := make([]ExtractionResult, 0, len(restores))
	for _, rf := range restores {
		name := rf.version.Name
		if rf.err == nil && rf.pending != 0 {
			rf.err = recoverable(ErrCodeIntegrityFail, "file is missing chunks", nil)
		}
		if rf.err == nil {
			rf.err = publishRestore(rf)
		}
		if rf.err != nil {
			se.progress.FileError(name, rf.err)
			results = append(results, ExtractionResult{Filename: name, Err: rf.err})
			continue
		}
		se.progress.FileStarted(name, int64(rf.version.Size))
		se.progress.FileFinished(name)
		results = append(results, ExtractionResult{Filename: name, Size: int64(rf.version.Size), OK: true})
	}
	return results
}

func publishRestore(rf *restoreFile) error {
	if err := os.Chmod(rf.tmpPath, os.FileMode(rf.version.Mode).Perm()); err != nil {
		return recoverable(ErrCodeWriteFailed, "set permissions", err)
	}
	if err := os.Rename(rf.tmpPath, rf.outPath); err != nil {
		return recoverable(ErrCodeWriteFailed, "write file", err)
	}
	rf.tmpPath = ""
	return nil
}

// chunkRouter cuts a pack's plaintext stream into the needed chunks, which must be
// sorted by offset and must not overlap, and passes each chunk's stored bytes to
// deliver. Bytes outside needed chunks are skipped.
type chunkRouter struct {
	chunks  []chunkLocation
	needed  []uint64
	deliver func(n uint64, stored []byte) error
	idx     int
	pos     uint64
	buf     []byte
	err     error // the first deliver or framing error, reported over the sink wrapper
}

func (r *chunkRouter) feed(pt []byte) error {
	for len(pt) > 0 && r.idx < len(r.needed) {
		c := r.chunks[r.needed[r.idx]]
		if len(r.buf) == 0 {
			if r.pos < c.offset {
				skip := min(c.offset-r.pos, uint64(len(pt)))
				r.pos += skip
				pt = pt[skip:]
				continue
			}
			if r.pos > c.offset {
				r.err = recoverable(ErrCodeIntegrityFail, "overlapping chunks in pack", nil)
				return r.err
			}
		}
		take := min(uint64(c.stored)-uint64(len(r.buf)), uint64(len(pt)))
		r.buf = append(r.buf, pt[:take]...)
		r.pos += take
		pt = pt[take:]
		if len(r.buf) == int(c.stored) {
			if err := r.deliver(r.needed[r.idx], r.buf); err != nil {
				r.err = err
				return err
			}
			r.buf = r.buf[:0]
			r.idx++
		}
	}
	r.pos += uint64(len(pt))
	return nil
}
