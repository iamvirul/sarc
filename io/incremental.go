// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bufio"
	"errors"
	"io"
	"sort"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// entryReadBufferSize is the read buffer of a reader positioned at one entry.
const entryReadBufferSize = 256 << 10

// incrementalArchive is the authenticated state of an incremental archive as of its
// newest complete session.
type incrementalArchive struct {
	keys      *archive.KeySchedule
	header    headerInfo
	sessions  uint64
	lastIndex int64  // offset of the newest index entry
	tail      int64  // offset where the next session is written
	hashState []byte // checksum state at tail; nil when the state was recovered
	recovered bool   // the tail was damaged, so the state was rebuilt by scanning
	chunks    []chunkLocation
	files     map[string]archive.FileVersion
}

// chunkLocation is where one chunk's stored bytes live.
type chunkLocation struct {
	id         [crypto.HMACSize]byte
	packOffset int64
	offset     uint64
	stored     uint32
	raw        uint32
	codec      archive.Codec
}

// sortedFiles returns the current files ordered by name.
func (ia *incrementalArchive) sortedFiles() []archive.FileVersion {
	files := make([]archive.FileVersion, 0, len(ia.files))
	for _, f := range ia.files {
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files
}

// openIncremental loads the state of the incremental archive whose header se has read.
func (se *SafeExtractor) openIncremental(keys *archive.KeySchedule) (*incrementalArchive, error) {
	if se.random == nil {
		return nil, fatal(ErrCodeInvalidOption, "incremental archives must be read from a file, not a pipe", nil)
	}
	proper, _, err := splitSignature(se.random, se.randomSize)
	if err != nil {
		return nil, err
	}
	return loadIncremental(se.random, proper, keys, se.header)
}

// loadIncremental reads the incremental archive in the first size bytes of ra (the
// archive proper, without any signature block). It reads the session index chain from the newest session back to the
// first and applies it in order. The newest session is found through the checkpoint,
// or, when the tail is damaged (an interrupted update), by scanning forward for the
// last complete index. A newest session older than the header's sealed session count
// means sessions were cut off, and is refused.
func loadIncremental(ra io.ReaderAt, size int64, keys *archive.KeySchedule, header headerInfo) (*incrementalArchive, error) {
	ia := &incrementalArchive{keys: keys, header: header, files: map[string]archive.FileVersion{}}
	var err error
	ia.lastIndex, ia.tail, ia.hashState, err = readCheckpoint(ra, size, header.end())
	if err != nil {
		if ia.lastIndex, ia.tail, err = scanForLastIndex(ra, size, keys, header.end()); err != nil {
			return nil, err
		}
		ia.recovered = true
	}
	chain, offsets, err := readIndexChain(ra, size, keys, header.end(), ia.lastIndex)
	if err != nil {
		return nil, err
	}
	newest := chain[len(chain)-1].Session
	if newest < header.sealedCount {
		return nil, fatal(ErrCodeIntegrityFail, "incremental archive is missing its newest sessions", nil)
	}
	for i, si := range chain {
		if err := ia.apply(si, offsets[i]); err != nil {
			return nil, err
		}
	}
	ia.sessions = newest
	return ia, nil
}

// readCheckpoint parses the tail of an intact incremental archive and returns the
// newest index offset, the offset of the tail, and the checksum state there.
func readCheckpoint(ra io.ReaderAt, size, headerEnd int64) (int64, int64, []byte, error) {
	tail := size - int64(archive.TailSize)
	if tail < headerEnd {
		return 0, 0, nil, fatal(ErrCodeTruncated, "incremental archive is too short", nil)
	}
	buf := make([]byte, archive.TailSize)
	if _, err := ra.ReadAt(buf, tail); err != nil {
		return 0, 0, nil, fatal(ErrCodeReadFailed, "read archive tail", err)
	}
	cp, err := archive.ParseCheckpoint(buf[:archive.CheckpointSize])
	if err != nil || buf[archive.CheckpointSize] != archive.EntryTypeEnd {
		return 0, 0, nil, fatal(ErrCodeIntegrityFail, "damaged archive tail", err)
	}
	if cp.LastIndex < uint64(headerEnd) || cp.LastIndex >= uint64(tail) {
		return 0, 0, nil, fatal(ErrCodeIntegrityFail, "checkpoint points outside the archive", nil)
	}
	return int64(cp.LastIndex), tail, cp.HashState, nil
}

// byteCounter counts the bytes read through it.
type byteCounter struct {
	r io.Reader
	n int64
}

func (c *byteCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// entryReaderAt returns an extractor reading the archive sequentially from offset, and
// the count of bytes it has consumed.
func entryReaderAt(ra io.ReaderAt, size, offset int64) (*SafeExtractor, *byteCounter) {
	counter := &byteCounter{r: bufio.NewReaderSize(io.NewSectionReader(ra, offset, size-offset), entryReadBufferSize)}
	return &SafeExtractor{r: counter, progress: NopProgressTracker{}}, counter
}

// readIndexChain reads the index at lastIndex and each previous one down to session 1,
// and returns them oldest first with their offsets. Sessions must count down by one
// and each previous index must lie before the current one.
func readIndexChain(ra io.ReaderAt, size int64, keys *archive.KeySchedule, headerEnd, lastIndex int64) ([]*archive.SessionIndex, []int64, error) {
	var chain []*archive.SessionIndex
	var offsets []int64
	for off := lastIndex; ; {
		si, err := readIndexAt(ra, size, keys, off)
		if err != nil {
			return nil, nil, err
		}
		if len(chain) > 0 && si.Session != chain[len(chain)-1].Session-1 {
			return nil, nil, fatal(ErrCodeIntegrityFail, "session index chain is out of order", nil)
		}
		chain, offsets = append(chain, si), append(offsets, off)
		if si.Session == 1 {
			if si.PrevIndex != 0 {
				return nil, nil, fatal(ErrCodeIntegrityFail, "first session index has a predecessor", nil)
			}
			break
		}
		if si.PrevIndex < uint64(headerEnd) || si.PrevIndex >= uint64(off) {
			return nil, nil, fatal(ErrCodeIntegrityFail, "session index chain points outside the archive", nil)
		}
		off = int64(si.PrevIndex)
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
		offsets[i], offsets[j] = offsets[j], offsets[i]
	}
	return chain, offsets, nil
}

// readIndexAt reads and authenticates the index entry at offset.
func readIndexAt(ra io.ReaderAt, size int64, keys *archive.KeySchedule, offset int64) (*archive.SessionIndex, error) {
	sub, _ := entryReaderAt(ra, size, offset)
	var entryType [1]byte
	if _, err := io.ReadFull(sub.r, entryType[:]); err != nil {
		return nil, fatal(ErrCodeTruncated, "read session index", err)
	}
	if entryType[0] != archive.EntryTypeIndex {
		return nil, fatal(ErrCodeIntegrityFail, "expected a session index entry", nil)
	}
	return sub.readIndexBody(keys)
}

// readIndexBody reads the rest of an index entry after its type byte, verifies its
// HMAC, and parses it. Any failure is fatal: the archive's state depends on every index.
func (se *SafeExtractor) readIndexBody(keys *archive.KeySchedule) (*archive.SessionIndex, error) {
	head, err := se.readEntryHead(keys)
	if err != nil {
		return nil, fatal(ErrCodeIntegrityFail, "open session index", err)
	}
	if err := se.skipPadding(); err != nil {
		return nil, fatal(ErrCodeTruncated, "skip index padding", err)
	}
	var plaintext []byte
	err = se.streamDataBlocks(head.fileKey, archive.BucketHuge, archive.CodecNone, nil, func(pt []byte) error {
		if len(plaintext)+len(pt) > archive.MaxIndexSize {
			return errIndexTooLarge
		}
		plaintext = append(plaintext, pt...)
		return nil
	})
	if err != nil {
		return nil, fatal(ErrCodeIntegrityFail, "decrypt session index", err)
	}
	trailer, err := se.readTrailer(head.fileKey, keys.Version())
	if err != nil {
		return nil, fatal(ErrCodeIntegrityFail, "read session index trailer", err)
	}
	if err := verifyPlaintext(head.fileKey, plaintext, trailer); err != nil {
		return nil, fatal(ErrCodeIntegrityFail, "session index failed verification", err)
	}
	si, err := archive.ParseSessionIndex(plaintext)
	if err != nil {
		return nil, fatal(ErrCodeIntegrityFail, "parse session index", err)
	}
	return si, nil
}

// errIndexTooLarge stops reading an index that exceeds archive.MaxIndexSize.
var errIndexTooLarge = errors.New("session index exceeds maximum size")

// scanForLastIndex walks the entries after the header and returns the offset of the
// last index entry that reads and verifies completely, and the offset just past it.
// It stops at the first entry that is truncated, damaged, or not part of a session.
func scanForLastIndex(ra io.ReaderAt, size int64, keys *archive.KeySchedule, start int64) (int64, int64, error) {
	sub, consumed := entryReaderAt(ra, size, start)
	lastIndex, end := int64(-1), int64(0)
	for {
		entryStart := start + consumed.n
		var entryType [1]byte
		if _, err := io.ReadFull(sub.r, entryType[:]); err != nil {
			break
		}
		if entryType[0] == archive.EntryTypePack {
			if _, err := sub.readEntryHead(keys); err != nil {
				break
			}
			if err := sub.skipEntryBody(nil); err != nil {
				break
			}
			continue
		}
		if entryType[0] != archive.EntryTypeIndex {
			break
		}
		if _, err := sub.readIndexBody(keys); err != nil {
			break
		}
		lastIndex, end = entryStart, start+consumed.n
	}
	if lastIndex < 0 {
		return 0, 0, fatal(ErrCodeIntegrityFail, "incremental archive has no complete session", nil)
	}
	return lastIndex, end, nil
}

// apply adds one session's chunks and file changes to the state. Packs must lie between
// the header and the session's index, chunk numbering must continue the previous
// session's, and each file's chunks must add up to its size.
func (ia *incrementalArchive) apply(si *archive.SessionIndex, indexOffset int64) error {
	if si.FirstChunk != uint64(len(ia.chunks)) {
		return fatal(ErrCodeIntegrityFail, "session index chunk numbering is inconsistent", nil)
	}
	for _, p := range si.Packs {
		if p < uint64(ia.header.end()) || p >= uint64(indexOffset) {
			return fatal(ErrCodeIntegrityFail, "pack lies outside its session", nil)
		}
	}
	for _, c := range si.Chunks {
		ia.chunks = append(ia.chunks, chunkLocation{
			id: c.ID, packOffset: int64(si.Packs[c.Pack]), offset: c.Offset,
			stored: c.StoredLen, raw: c.RawLen, codec: c.Codec,
		})
	}
	for _, f := range si.Files {
		var total uint64
		for _, n := range f.Chunks {
			total += uint64(ia.chunks[n].raw)
		}
		if total != f.Size {
			return fatal(ErrCodeIntegrityFail, "file size does not match its chunks", nil)
		}
		ia.files[f.Name] = f
	}
	for _, name := range si.Deleted {
		delete(ia.files, name)
	}
	return nil
}

// listIncremental lists the current files of an incremental archive.
func (se *SafeExtractor) listIncremental(keys *archive.KeySchedule) ([]ListResult, error) {
	ia, err := se.openIncremental(keys)
	if err != nil {
		return nil, err
	}
	files := ia.sortedFiles()
	results := make([]ListResult, 0, len(files))
	for _, f := range files {
		var stored int64
		for _, n := range f.Chunks {
			stored += int64(ia.chunks[n].stored)
		}
		results = append(results, ListResult{
			Filename:      f.Name,
			SizeBucket:    bucketName(archive.BucketizeSize(int64(f.Size))),
			Codec:         "chunked",
			OriginalBytes: int64(f.Size),
			StoredBytes:   stored,
		})
	}
	return results, nil
}
