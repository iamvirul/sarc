// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bufio"
	"bytes"
	stdhmac "crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// incrementalTempPattern names a new incremental archive until its first session is
// complete, so an interrupted creation never leaves a broken archive at the real path.
const incrementalTempPattern = ".sarc-incremental-*"

// IncrementalOptions configures ArchiveIncremental.
type IncrementalOptions struct {
	// Password protects a new archive (empty for none).
	Password string
	// UnlockPassword, KeyFiles, and Identities are tried to open an existing archive.
	UnlockPassword string
	KeyFiles       [][]byte
	Identities     []age.Identity
	// Archiver holds a new archive's other credentials (WithKeyFileRecipients,
	// WithAgeRecipients) and the compression options for new chunks. The credentials of
	// an existing archive are fixed, so its credential options are ignored.
	Archiver []ArchiverOption
	Progress ProgressTracker
}

// IncrementalResult summarises one ArchiveIncremental run.
type IncrementalResult struct {
	Session       uint64 // the archive's newest session after the run
	Created       bool
	Changed       int   // new or modified files recorded
	Unchanged     int   // files skipped because size, modification time, and mode match
	Deleted       int   // files recorded as deleted
	Failed        int   // files that could not be read; their previous versions are kept
	ChangedBytes  int64 // total size of the changed files
	NewChunks     int
	AppendedBytes int64 // how much the archive grew, not counting its signature
	Repaired      bool  // a damaged tail left by an interrupted update was rebuilt
	// Signed reports that this run wrote a signature with the WithSigner key. A run that
	// changes nothing keeps a signature that still holds for that key and reports false.
	Signed bool
	// SignatureRemoved reports that the run changed a signed archive without a signer,
	// so its signature, which no longer matched, was removed.
	SignatureRemoved bool
}

// ArchiveIncremental records the current state of inputs (files and directories,
// expanded as by the other archivers) in the incremental archive at path, creating it
// when path does not exist. An update writes only chunks the archive does not already
// hold, plus an index of new, changed, and deleted files; a file whose size,
// modification time, and mode are unchanged is not read, and a run that finds no
// change writes nothing.
//
// An input argument that cannot be read fails the run instead of recording its files
// as deleted; a file or directory inside one that cannot be read keeps its previous
// version.
func ArchiveIncremental(path string, inputs []string, opts IncrementalOptions) (IncrementalResult, error) {
	if opts.Progress == nil {
		opts.Progress = NopProgressTracker{}
	}
	cfg := newArchiverConfig(opts.Archiver)
	if cfg.compression.Solid {
		return IncrementalResult{}, fatal(ErrCodeInvalidOption, "solid mode does not apply to incremental archives", nil)
	}
	files, skipped := expandInputs(inputs, cfg.walkOptions())
	for _, s := range skipped {
		if s.unreadable && s.name == "" {
			return IncrementalResult{}, fatal(ErrCodeReadFailed,
				fmt.Sprintf("cannot read %s; refusing to record its files as deleted", s.path), s.err)
		}
	}
	reportSkipped(skipped, opts.Progress)

	switch _, err := os.Stat(path); {
	case errors.Is(err, fs.ErrNotExist):
		return createIncremental(path, files, cfg, opts)
	case err != nil:
		return IncrementalResult{}, fatal(ErrCodeReadFailed, "stat archive", err)
	}
	return updateIncremental(path, files, skipped, cfg, opts)
}

// createIncremental writes a new incremental archive holding files as session 1. It is
// written to a temporary file beside path and renamed into place once complete.
func createIncremental(path string, files []inputFile, cfg archiverConfig, opts IncrementalOptions) (IncrementalResult, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), incrementalTempPattern)
	if err != nil {
		return IncrementalResult{}, fatal(ErrCodeWriteFailed, "create archive", err)
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()
	aw, err := newCredentialedWriter(tmp, opts.Password, cfg)
	if err != nil {
		return IncrementalResult{}, err
	}
	if err := aw.WriteHeaderWithFlags(1, archive.HeaderFlagIncremental); err != nil {
		return IncrementalResult{}, fatal(ErrCodeWriteFailed, "write header", err)
	}
	ia := &incrementalArchive{keys: aw.Keys(), files: map[string]archive.FileVersion{}}
	changed := make([]changedFile, 0, len(files))
	for _, in := range files {
		if !in.regular() {
			changed = append(changed, changedFile{in: in})
			continue
		}
		if info, err := os.Stat(in.path); err == nil {
			changed = append(changed, changedFile{in: in, info: info})
		} else {
			changed = append(changed, changedFile{in: in, err: recoverable(ErrCodeReadFailed, "stat file", err)})
		}
	}
	res, err := writeSession(aw, ia, changed, nil, cfg.compression, opts.Progress, true)
	if err != nil {
		return res, err
	}
	if cfg.signer != nil {
		block, err := signatureBlock(aw.Checksum(), cfg.signer)
		if err != nil {
			return res, err
		}
		if _, err := tmp.Write(block); err != nil {
			return res, fatal(ErrCodeWriteFailed, "write signature", err)
		}
		res.Signed = true
	}
	if err := tmp.Sync(); err != nil {
		return res, fatal(ErrCodeWriteFailed, "sync archive", err)
	}
	if err := tmp.Close(); err != nil {
		return res, fatal(ErrCodeWriteFailed, "close archive", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return res, fatal(ErrCodeWriteFailed, "move archive into place", err)
	}
	res.Created = true
	res.AppendedBytes = aw.Offset() + archive.FooterSize
	return res, nil
}

// changedFile is an input to record in a session, or the error that prevents it. info
// is set for regular files.
type changedFile struct {
	in   inputFile
	info fs.FileInfo
	err  error
}

// updateIncremental appends a session to the incremental archive at path when files
// differ from its newest state. A signature is renewed with cfg's signer, or removed
// when the archive changes without one.
func updateIncremental(path string, files []inputFile, skipped []skippedInput, cfg archiverConfig, opts IncrementalOptions) (IncrementalResult, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return IncrementalResult{}, fatal(ErrCodeReadFailed, "open archive", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return IncrementalResult{}, fatal(ErrCodeReadFailed, "stat archive", err)
	}
	se := &SafeExtractor{
		r:        bufio.NewReader(io.NewSectionReader(f, 0, info.Size())),
		password: opts.UnlockPassword, keyFiles: opts.KeyFiles, identities: opts.Identities,
		progress: NopProgressTracker{},
	}
	keys, err := se.readHeader()
	if err != nil {
		return IncrementalResult{}, err
	}
	if !se.header.incremental() {
		return IncrementalResult{}, fatal(ErrCodeInvalidOption, "the output exists and is not an incremental archive", nil)
	}
	proper, signature, err := splitSignature(f, info.Size())
	if err != nil {
		return IncrementalResult{}, err
	}
	ia, err := loadIncremental(f, proper, keys, se.header)
	if err != nil {
		return IncrementalResult{}, err
	}
	res := IncrementalResult{Session: ia.sessions}
	size := info.Size()
	var checksum []byte // the footer checksum, when this run has computed it
	if ia.recovered {
		if checksum, err = repairTail(f, ia); err != nil {
			return res, err
		}
		res.Repaired = true
		size = ia.tail + int64(archive.TailSize)
	}

	changed, deleted, unchanged := diffInputs(ia, files, skipped)
	res.Unchanged = unchanged
	if len(changed) == 0 && len(deleted) == 0 {
		return finishUnchanged(f, ia, res, signature, checksum, cfg.signer)
	}
	res, checksum, end, err := appendSession(f, ia, changed, deleted, cfg, opts.Progress, res, size)
	if err != nil || checksum == nil {
		return res, err
	}
	switch {
	case cfg.signer != nil:
		if err := writeSignature(f, end, checksum, cfg.signer); err != nil {
			return res, err
		}
		res.Signed = true
	case signature != nil:
		res.SignatureRemoved = true
	}
	return res, nil
}

// finishUnchanged completes a run that records no change. A signature that still holds
// for the signer is kept; otherwise, with a signer, the archive is signed after its
// checksum is verified. A repair without a signer removed the old signature.
func finishUnchanged(f *os.File, ia *incrementalArchive, res IncrementalResult, signature, checksum []byte, signer ssh.Signer) (IncrementalResult, error) {
	end := ia.tail + int64(archive.TailSize)
	if signer == nil {
		res.SignatureRemoved = res.Repaired && signature != nil
		return res, nil
	}
	if checksum == nil {
		footer := make([]byte, archive.HMACSize)
		if _, err := f.ReadAt(footer, end-archive.FooterSize); err != nil {
			return res, fatal(ErrCodeReadFailed, "read footer", err)
		}
		if signature != nil && signedBy(signature, footer, signer.PublicKey()) {
			return res, nil
		}
		var err error
		if checksum, err = archiveChecksum(f, end); err != nil {
			return res, err
		}
	}
	if err := writeSignature(f, end, checksum, signer); err != nil {
		return res, err
	}
	res.Signed = true
	return res, nil
}

// diffInputs compares files with the archive's newest state. An entry is changed when
// it is new, or its kind, size, modification time, mode, link target, owner, or
// extended attributes differ. A previous entry is deleted when it was not found,
// unless it lies in a directory that could not be read.
func diffInputs(ia *incrementalArchive, files []inputFile, skipped []skippedInput) ([]changedFile, []string, int) {
	seen := make(map[string]bool, len(files))
	var changed []changedFile
	unchanged := 0
	for _, in := range files {
		seen[in.name] = true
		prev, known := ia.files[in.name]
		if !in.regular() {
			if known && sameAttributes(prev.Attributes, in.attrs) {
				unchanged++
			} else {
				changed = append(changed, changedFile{in: in})
			}
			continue
		}
		info, err := os.Stat(in.path)
		if err != nil {
			changed = append(changed, changedFile{in: in, err: recoverable(ErrCodeReadFailed, "stat file", err)})
			continue
		}
		if known && prev.Size == uint64(info.Size()) && sameAttributes(prev.Attributes, in.attrs) {
			unchanged++
			continue
		}
		changed = append(changed, changedFile{in: in, info: info})
	}
	var protected []string
	for _, s := range skipped {
		if s.unreadable && s.name != "" {
			protected = append(protected, s.name)
		}
	}
	var deleted []string
	for _, prev := range ia.sortedFiles() {
		if !seen[prev.Name] && !underAny(prev.Name, protected) {
			deleted = append(deleted, prev.Name)
		}
	}
	return changed, deleted, unchanged
}

// sameAttributes reports whether a and b describe the same entry state.
func sameAttributes(a, b archive.Attributes) bool {
	if a.Kind != b.Kind || a.Mode != b.Mode || a.ModTime != b.ModTime || a.LinkTarget != b.LinkTarget ||
		(a.Owner == nil) != (b.Owner == nil) || (a.Owner != nil && *a.Owner != *b.Owner) || len(a.Xattrs) != len(b.Xattrs) {
		return false
	}
	for i := range a.Xattrs {
		if a.Xattrs[i].Name != b.Xattrs[i].Name || !bytes.Equal(a.Xattrs[i].Value, b.Xattrs[i].Value) {
			return false
		}
	}
	return true
}

// underAny reports whether name is one of prefixes or inside a directory named by one.
func underAny(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if name == p || strings.HasPrefix(name, p+"/") {
			return true
		}
	}
	return false
}

// repairTail rebuilds the tail of an archive whose last update was interrupted: it cuts
// everything after the last complete session and writes a fresh checkpoint, end
// marker, and footer, rehashing the archive once to recover the checksum state. It
// returns the new footer checksum.
func repairTail(f *os.File, ia *incrementalArchive) ([]byte, error) {
	sum := archive.NewArchiveChecksum()
	if _, err := io.Copy(sum, io.NewSectionReader(f, 0, ia.tail)); err != nil {
		return nil, fatal(ErrCodeReadFailed, "rehash archive", err)
	}
	state, err := sum.MarshalBinary()
	if err != nil {
		return nil, fatal(ErrCodeWriteFailed, "save checksum state", err)
	}
	checksum, err := writeTail(f, ia, ia.tail, state, ia.lastIndex)
	if err != nil {
		return nil, err
	}
	ia.hashState, ia.recovered = state, false
	return checksum, nil
}

// writeTail writes a checkpoint for lastIndex, the end marker, and the footer at
// offset, truncates the file after them, syncs it, and returns the footer checksum.
func writeTail(f *os.File, ia *incrementalArchive, offset int64, hashState []byte, lastIndex int64) ([]byte, error) {
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, fatal(ErrCodeWriteFailed, "seek archive", err)
	}
	aw, err := archive.ResumeArchiveWriter(f, ia.keys, offset, hashState)
	if err != nil {
		return nil, fatal(ErrCodeIntegrityFail, "resume archive", err)
	}
	if err := aw.WriteCheckpointFooter(lastIndex); err != nil {
		return nil, fatal(ErrCodeWriteFailed, "write archive tail", err)
	}
	return aw.Checksum(), truncateAndSync(f, aw.Offset()+archive.FooterSize)
}

func truncateAndSync(f *os.File, size int64) error {
	if err := f.Truncate(size); err != nil {
		return fatal(ErrCodeWriteFailed, "truncate archive", err)
	}
	if err := f.Sync(); err != nil {
		return fatal(ErrCodeWriteFailed, "sync archive", err)
	}
	return nil
}

// appendSession writes a new session over the archive's tail in a file of size bytes,
// then reseals the header's session count. It returns the new footer checksum and the
// end of the archive, or a nil checksum when no session was written. If writing fails,
// everything from the previous tail on (any signature included) is restored, so the
// archive is left exactly as it was.
func appendSession(f *os.File, ia *incrementalArchive, changed []changedFile, deleted []string, cfg archiverConfig, progress ProgressTracker, res IncrementalResult, size int64) (IncrementalResult, []byte, int64, error) {
	oldTail := make([]byte, size-ia.tail)
	if _, err := f.ReadAt(oldTail, ia.tail); err != nil {
		return res, nil, 0, fatal(ErrCodeReadFailed, "read archive tail", err)
	}
	archiveEnd := ia.tail + int64(archive.TailSize)
	if _, err := f.Seek(ia.tail, io.SeekStart); err != nil {
		return res, nil, 0, fatal(ErrCodeWriteFailed, "seek archive", err)
	}
	aw, err := archive.ResumeArchiveWriter(f, ia.keys, ia.tail, ia.hashState)
	if err != nil {
		return res, nil, 0, fatal(ErrCodeIntegrityFail, "resume archive", err)
	}
	restore := func(cause error) error {
		if _, err := f.WriteAt(oldTail, ia.tail); err != nil {
			return fatal(ErrCodeWriteFailed, "restore archive tail", err)
		}
		if err := truncateAndSync(f, size); err != nil {
			return err
		}
		return cause
	}

	sessionRes, err := writeSession(aw, ia, changed, deleted, cfg.compression, progress, false)
	if errors.Is(err, errEmptySession) {
		res.Failed = sessionRes.Failed
		return res, nil, 0, restore(nil)
	}
	if err != nil {
		return res, nil, 0, restore(err)
	}
	end := aw.Offset() + archive.FooterSize
	if err := truncateAndSync(f, end); err != nil {
		return res, nil, 0, restore(err)
	}
	sealed, err := archive.SealFileCount(ia.keys, sessionRes.Session)
	if err != nil {
		return res, nil, 0, fatal(ErrCodeWriteFailed, "seal session count", err)
	}
	if _, err := f.WriteAt(sealed[:], archive.FileCountOffset(ia.header.recipientBlockLen)); err != nil {
		return res, nil, 0, fatal(ErrCodeWriteFailed, "write session count", err)
	}
	if err := f.Sync(); err != nil {
		return res, nil, 0, fatal(ErrCodeWriteFailed, "sync archive", err)
	}
	sessionRes.Unchanged, sessionRes.Repaired = res.Unchanged, res.Repaired
	sessionRes.AppendedBytes = end - archiveEnd
	return sessionRes, aw.Checksum(), end, nil
}

// errEmptySession reports that a session recorded nothing, so it is not written.
var errEmptySession = errors.New("session records no change")

// writeSession records changed and deleted files as the session after ia's newest:
// new chunks go into pack entries, then the session index and the archive tail follow.
// Unless allowEmpty is set, a session in which no file could be recorded and nothing
// was deleted stops with errEmptySession before its index is written.
func writeSession(aw *archive.ArchiveWriter, ia *incrementalArchive, changed []changedFile, deleted []string, compression CompressionOptions, progress ProgressTracker, allowEmpty bool) (IncrementalResult, error) {
	start := time.Now()
	sw, err := newSessionWriter(aw, ia, compression, progress)
	if err != nil {
		return IncrementalResult{}, err
	}
	res := IncrementalResult{Session: ia.sessions + 1, Deleted: len(deleted)}
	for _, c := range changed {
		if c.err != nil {
			progress.FileError(c.in.path, c.err)
			res.Failed++
			continue
		}
		if !c.in.regular() {
			sw.index.Files = append(sw.index.Files, archive.FileVersion{Name: c.in.name, Attributes: c.in.attrs, Chunks: []uint64{}})
			res.Changed++
			continue
		}
		version, err := sw.addFile(c.in, c.info)
		if err != nil {
			if isFatal(err) {
				return res, err
			}
			progress.FileError(c.in.path, err)
			res.Failed++
			continue
		}
		sw.index.Files = append(sw.index.Files, version)
		res.Changed++
		res.ChangedBytes += int64(version.Size)
	}
	if !allowEmpty && res.Changed == 0 && len(deleted) == 0 {
		return res, errEmptySession
	}
	if err := sw.closePack(); err != nil {
		return res, err
	}
	sw.index.Deleted = deleted
	indexOffset, err := sw.writeIndex()
	if err != nil {
		return res, err
	}
	if err := aw.WriteCheckpointFooter(indexOffset); err != nil {
		return res, fatal(ErrCodeWriteFailed, "write archive tail", err)
	}
	res.NewChunks = len(sw.index.Chunks)
	progress.Done(res.Changed, res.ChangedBytes, time.Since(start))
	return res, nil
}

// sessionWriter chunks files and appends new chunks to pack entries for one session.
type sessionWriter struct {
	aw          *archive.ArchiveWriter
	ia          *incrementalArchive
	idKey       [crypto.KeySize]byte
	gear        [crypto.GearTableSize]uint64
	policy      *compressionPolicy
	compressor  *archive.BlockCompressor // nil when compression is off
	compressBuf []byte
	known       map[[crypto.HMACSize]byte]uint64
	index       archive.SessionIndex
	pack        *packWriter
	progress    ProgressTracker
}

func newSessionWriter(aw *archive.ArchiveWriter, ia *incrementalArchive, compression CompressionOptions, progress ProgressTracker) (*sessionWriter, error) {
	policy, err := newCompressionPolicy(compression)
	if err != nil {
		return nil, fatal(ErrCodeInvalidOption, "invalid compression options", err)
	}
	sw := &sessionWriter{
		aw: aw, ia: ia, policy: policy, progress: progress,
		known: make(map[[crypto.HMACSize]byte]uint64, len(ia.chunks)),
		index: archive.SessionIndex{
			Session: ia.sessions + 1, Time: time.Now().Unix(),
			PrevIndex: uint64(ia.lastIndex), FirstChunk: uint64(len(ia.chunks)),
		},
	}
	if sw.idKey, err = ia.keys.ChunkIDKey(); err != nil {
		return nil, fatal(ErrCodeWriteFailed, "derive chunk key", err)
	}
	if sw.gear, err = ia.keys.GearTable(); err != nil {
		return nil, fatal(ErrCodeWriteFailed, "derive chunker table", err)
	}
	if compression.Mode != CompressionNever {
		if sw.compressor, err = archive.NewChunkCompressor(compression.Level); err != nil {
			return nil, fatal(ErrCodeInvalidOption, "invalid compression options", err)
		}
	}
	for n, c := range ia.chunks {
		sw.known[c.id] = uint64(n)
	}
	return sw, nil
}

// addFile chunks the file and stores each chunk the archive does not hold yet.
func (sw *sessionWriter) addFile(in inputFile, info fs.FileInfo) (archive.FileVersion, error) {
	f, err := os.Open(in.path)
	if err != nil {
		return archive.FileVersion{}, recoverable(ErrCodeReadFailed, "open file", err)
	}
	defer f.Close()
	sw.progress.FileStarted(in.name, info.Size())
	probe, err := readProbe(f, info.Size(), sw.policy.mode)
	if err != nil {
		return archive.FileVersion{}, recoverable(ErrCodeReadFailed, "read compression probe", err)
	}
	codec := sw.policy.codecFor(in.name, probe)

	chunker := archive.NewChunker(f, &sw.gear)
	version := archive.FileVersion{Name: in.name, Attributes: in.attrs, Chunks: []uint64{}}
	for {
		chunk, err := chunker.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return archive.FileVersion{}, recoverable(ErrCodeReadFailed, "read file", err)
		}
		version.Size += uint64(len(chunk))
		sw.progress.BytesProcessed(int64(len(chunk)))
		id := crypto.ComputeHMAC(sw.idKey, chunk)
		n, ok := sw.known[id]
		if !ok {
			if n, err = sw.storeChunk(id, chunk, codec); err != nil {
				return archive.FileVersion{}, err
			}
		}
		version.Chunks = append(version.Chunks, n)
	}
	sw.progress.FileFinished(in.name)
	return version, nil
}

// storeChunk appends a new chunk to the current pack, compressed when the file's codec
// is zstd and that makes it smaller, and returns its global chunk number.
func (sw *sessionWriter) storeChunk(id [crypto.HMACSize]byte, chunk []byte, codec archive.Codec) (uint64, error) {
	stored, storedCodec := chunk, archive.CodecNone
	if codec == archive.CodecZstd && sw.compressor != nil {
		sw.compressBuf = sw.compressor.Compress(sw.compressBuf[:0], chunk)
		if len(sw.compressBuf) < len(chunk) {
			stored, storedCodec = sw.compressBuf, archive.CodecZstd
		}
	}
	if sw.pack != nil && sw.pack.size+uint64(len(stored)) > archive.MaxPackSize {
		if err := sw.closePack(); err != nil {
			return 0, err
		}
	}
	if sw.pack == nil {
		sw.index.Packs = append(sw.index.Packs, uint64(sw.aw.Offset()))
		pack, err := openPack(sw.aw)
		if err != nil {
			return 0, err
		}
		sw.pack = pack
	}
	offset := sw.pack.size
	if err := sw.pack.write(stored); err != nil {
		return 0, err
	}
	n := uint64(len(sw.ia.chunks))
	sw.index.Chunks = append(sw.index.Chunks, archive.ChunkRecord{
		ID: id, Pack: uint32(len(sw.index.Packs) - 1), Offset: offset,
		StoredLen: uint32(len(stored)), RawLen: uint32(len(chunk)), Codec: storedCodec,
	})
	sw.ia.chunks = append(sw.ia.chunks, chunkLocation{
		id: id, packOffset: int64(sw.index.Packs[len(sw.index.Packs)-1]), offset: offset,
		stored: uint32(len(stored)), raw: uint32(len(chunk)), codec: storedCodec,
	})
	sw.known[id] = n
	return n, nil
}

func (sw *sessionWriter) closePack() error {
	if sw.pack == nil {
		return nil
	}
	err := sw.pack.close()
	sw.pack = nil
	return err
}

// writeIndex seals the session index as an index entry and returns its offset.
func (sw *sessionWriter) writeIndex() (int64, error) {
	plaintext, err := sw.index.Marshal()
	if err != nil {
		return 0, fatal(ErrCodeWriteFailed, "encode session index", err)
	}
	entry, err := sealPayloadEntry(sw.aw, archive.EntryTypeIndex, archive.CodecNone, plaintext, plaintext)
	if err != nil {
		return 0, err
	}
	offset := sw.aw.Offset()
	if err := sw.aw.WriteFileEntry(entry); err != nil {
		return 0, fatal(ErrCodeWriteFailed, "write session index", err)
	}
	return offset, nil
}

// packWriter streams one pack entry: stored chunks are concatenated and sealed into
// data blocks of the usual random sizes, so chunk boundaries are not visible.
type packWriter struct {
	aw   *archive.ArchiveWriter
	fb   *archive.FrameBuilder
	mac  hash.Hash
	size uint64
	buf  []byte // plaintext not yet sealed
	next int    // size of the next block
}

func openPack(aw *archive.ArchiveWriter) (*packWriter, error) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return nil, fatal(ErrCodeWriteFailed, "generate salt", err)
	}
	key, err := aw.DeriveFileKey(salt)
	if err != nil {
		return nil, fatal(ErrCodeWriteFailed, "derive pack key", err)
	}
	fb, err := archive.NewFrameBuilder(key)
	if err != nil {
		return nil, fatal(ErrCodeWriteFailed, "init frame builder", err)
	}
	frameHdr, err := fb.FrameHeader()
	if err != nil {
		return nil, fatal(ErrCodeWriteFailed, "frame header", err)
	}
	mm, err := archive.NewMetadataManager(key)
	if err != nil {
		return nil, fatal(ErrCodeWriteFailed, "init metadata manager", err)
	}
	meta, err := mm.Seal(archive.PlaintextMetadata{SizeBucket: archive.BucketHuge, Codec: archive.CodecNone})
	if err != nil {
		return nil, fatal(ErrCodeWriteFailed, "seal metadata", err)
	}
	interPad, err := fb.InterBlockPadding()
	if err != nil {
		return nil, fatal(ErrCodeWriteFailed, "inter-block padding", err)
	}
	if err := aw.BeginFileEntry(archive.EntryTypePack, salt, frameHdr, meta, interPad); err != nil {
		return nil, fatal(ErrCodeWriteFailed, "begin pack", err)
	}
	return &packWriter{aw: aw, fb: fb, mac: stdhmac.New(sha256.New, key[:]), next: fb.NextChunkSize()}, nil
}

func (p *packWriter) write(data []byte) error {
	p.mac.Write(data)
	p.size += uint64(len(data))
	if len(p.buf) > 0 {
		take := min(p.next-len(p.buf), len(data))
		p.buf = append(p.buf, data[:take]...)
		data = data[take:]
		if len(p.buf) < p.next {
			return nil
		}
		if err := p.seal(p.buf); err != nil {
			return err
		}
		p.buf = p.buf[:0]
	}
	for len(data) >= p.next {
		n := p.next // seal draws the following size
		if err := p.seal(data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	p.buf = append(p.buf, data...)
	return nil
}

// seal encrypts one block and draws the size of the next.
func (p *packWriter) seal(block []byte) error {
	db, err := p.fb.EncryptChunk(block)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "encrypt pack block", err)
	}
	if err := p.aw.AppendDataBlock(db); err != nil {
		return fatal(ErrCodeWriteFailed, "write pack block", err)
	}
	p.next = p.fb.NextChunkSize()
	return nil
}

func (p *packWriter) close() error {
	if len(p.buf) > 0 {
		if err := p.seal(p.buf); err != nil {
			return err
		}
	}
	var sum [crypto.HMACSize]byte
	copy(sum[:], p.mac.Sum(nil))
	trailer, err := p.fb.BuildTrailer(sum, p.size)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "build pack trailer", err)
	}
	if err := p.aw.EndFileEntry(trailer); err != nil {
		return fatal(ErrCodeWriteFailed, "end pack", err)
	}
	return nil
}
