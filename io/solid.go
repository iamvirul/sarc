// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// solidPlan splits archive inputs into individually stored files and solid groups.
type solidPlan struct {
	individual []inputFile
	groups     [][]inputFile
}

// planSolid packs regular files of at most archive.SolidMemberMaxSize into groups whose
// estimated record stream fits archive.MaxSolidStreamSize. Candidates are ordered by
// extension so similar content shares a compression window. Everything else, including
// paths that cannot be stat'ed (their error surfaces when archived), stays individual,
// as does a group of one, where grouping gains nothing.
func planSolid(files []inputFile) solidPlan {
	type candidate struct {
		in     inputFile
		ext    string
		record int
	}
	var plan solidPlan
	var candidates []candidate
	for _, f := range files {
		record, ok := solidCandidate(f)
		if !ok {
			plan.individual = append(plan.individual, f)
			continue
		}
		candidates = append(candidates, candidate{in: f, ext: strings.ToLower(path.Ext(f.name)), record: record})
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].ext < candidates[j].ext })

	var group []inputFile
	groupSize := 0
	flush := func() {
		switch len(group) {
		case 0:
		case 1:
			plan.individual = append(plan.individual, group[0])
		default:
			plan.groups = append(plan.groups, group)
		}
		group, groupSize = nil, 0
	}
	for _, c := range candidates {
		if groupSize+c.record > archive.MaxSolidStreamSize {
			flush()
		}
		group = append(group, c.in)
		groupSize += c.record
	}
	flush()
	return plan
}

// solidCandidate reports whether in can join a solid group and, if so, the estimated
// size of its record: it must be a regular file of at most archive.SolidMemberMaxSize.
func solidCandidate(in inputFile) (int, bool) {
	info, err := os.Stat(in.path)
	if err != nil || !in.regular() || !info.Mode().IsRegular() || info.Size() > archive.SolidMemberMaxSize {
		return 0, false
	}
	return archive.SolidRecordSize(len(in.name), attributesSize(in.attrs), int(info.Size())), true
}

// attributesSize returns the encoded size of attrs, or 0 if they cannot be encoded
// (AppendSolidRecord then reports the error).
func attributesSize(attrs archive.Attributes) int {
	b, err := archive.AppendAttributes(nil, attrs)
	if err != nil {
		return 0
	}
	return len(b)
}

// solidMemberResult is the outcome of packing one file into a solid group.
type solidMemberResult struct {
	path string
	name string
	size int64
	err  error
}

// buildSolidEntry packs paths into one record stream, compresses it per policy, and
// seals it as a solid group entry. Members that cannot be read are skipped and reported
// in the results with recoverable errors. The entry is nil when no member was readable.
func buildSolidEntry(aw *archive.ArchiveWriter, policy *compressionPolicy, members []inputFile, progress ProgressTracker) (*archive.FileEntry, []solidMemberResult, error) {
	stream := make([]byte, 0, archive.MaxSolidStreamSize)
	results := make([]solidMemberResult, 0, len(members))
	packed := 0
	for _, m := range members {
		var res solidMemberResult
		stream, res = appendSolidMember(stream, m, progress)
		results = append(results, res)
		if res.err == nil {
			packed++
		}
	}
	if packed == 0 {
		return nil, results, nil
	}
	entry, err := sealSolidEntry(aw, policy, stream)
	if err != nil {
		return nil, results, err
	}
	return &entry, results, nil
}

// appendSolidMember reads in and appends its record to stream. On failure stream is
// returned unchanged and the result carries a recoverable error.
func appendSolidMember(stream []byte, in inputFile, progress ProgressTracker) ([]byte, solidMemberResult) {
	res := solidMemberResult{path: in.path, name: in.name}
	f, err := os.Open(in.path)
	if err != nil {
		res.err = recoverable(ErrCodeReadFailed, "open file", err)
		return stream, res
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		res.err = recoverable(ErrCodeReadFailed, "stat file", err)
		return stream, res
	}
	progress.FileStarted(in.name, info.Size())

	// Read one byte past the member limit to detect a file that grew after planning.
	data, err := io.ReadAll(io.LimitReader(&progressReader{r: f, progress: progress}, archive.SolidMemberMaxSize+1))
	if err != nil {
		res.err = recoverable(ErrCodeReadFailed, "read file", err)
		return stream, res
	}
	if len(data) > archive.SolidMemberMaxSize ||
		len(stream)+archive.SolidRecordSize(len(in.name), attributesSize(in.attrs), len(data)) > archive.MaxSolidStreamSize {
		res.err = recoverable(ErrCodeReadFailed, "file changed size during archive", nil)
		return stream, res
	}
	out, err := archive.AppendSolidRecord(stream, archive.SolidMember{
		Name:       in.name,
		Attributes: in.attrs,
		Data:       data,
	})
	if err != nil {
		res.err = recoverable(ErrCodeReadFailed, "unsupported file name", err)
		return stream, res
	}
	res.size = int64(len(data))
	return out, res
}

// sealSolidEntry compresses stream per policy and seals it as a solid group entry under
// a fresh entry salt. The HMAC and recorded size cover the uncompressed stream.
func sealSolidEntry(aw *archive.ArchiveWriter, policy *compressionPolicy, stream []byte) (archive.FileEntry, error) {
	codec := policy.solidCodecFor(stream)
	payload := stream
	if codec == archive.CodecZstd {
		payload = policy.solidCompressor.Compress(nil, stream)
	}
	return sealPayloadEntry(aw, archive.EntryTypeSolid, codec, payload, stream)
}

// sealPayloadEntry seals an in-memory entry of entryType under a fresh entry salt: its
// metadata records codec and plaintext's size bucket, payload (plaintext already
// encoded per codec) fills the data blocks, and the trailer HMAC and size cover
// plaintext.
func sealPayloadEntry(aw *archive.ArchiveWriter, entryType byte, codec archive.Codec, payload, plaintext []byte) (archive.FileEntry, error) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "generate salt", err)
	}
	fileKey, err := aw.DeriveFileKey(salt)
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "derive file key", err)
	}

	// The payload is already encoded, so the FrameBuilder seals chunks as-is.
	fb, err := archive.NewFrameBuilder(fileKey)
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "init frame builder", err)
	}
	frameHdr, err := fb.FrameHeader()
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "frame header", err)
	}
	mm, err := archive.NewMetadataManager(fileKey)
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "init metadata manager", err)
	}
	meta, err := mm.Seal(archive.PlaintextMetadata{
		SizeBucket: archive.BucketizeSize(int64(len(plaintext))),
		Codec:      codec,
	})
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "seal metadata", err)
	}
	interPad, err := fb.InterBlockPadding()
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "inter-block padding", err)
	}

	var blocks []archive.DataBlock
	for off := 0; off < len(payload); {
		n := min(fb.NextChunkSize(), len(payload)-off)
		db, err := fb.EncryptChunk(payload[off : off+n])
		if err != nil {
			return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "encrypt block", err)
		}
		blocks = append(blocks, db)
		off += n
	}

	trailer, err := fb.BuildTrailer(crypto.ComputeHMAC(fileKey, plaintext), uint64(len(plaintext)))
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "build trailer", err)
	}
	return archive.FileEntry{
		EntryType:     entryType,
		EntrySalt:     salt,
		FrameHdr:      frameHdr,
		Metadata:      meta,
		InterBlockPad: interPad,
		DataBlocks:    blocks,
		Trailer:       trailer,
	}, nil
}

// solidCodecFor returns the codec for a solid group stream. Extension skipping does not
// apply: zstd stores incompressible members cheaply, and the group shares one decision.
// Without a solid compressor (solid mode off, or CompressionNever) it is CodecNone.
func (p *compressionPolicy) solidCodecFor(stream []byte) archive.Codec {
	if p.solidCompressor == nil {
		return archive.CodecNone
	}
	return p.codecFor("", stream[:min(len(stream), compressionProbeSize)])
}

// reportSolidMembers forwards per-member outcomes of a written solid group to progress
// and returns the total bytes packed.
func reportSolidMembers(members []solidMemberResult, progress ProgressTracker) int64 {
	var total int64
	for _, m := range members {
		if m.err != nil {
			progress.FileError(m.path, m.err)
			continue
		}
		total += m.size
		progress.FileFinished(m.name)
	}
	return total
}

// readSolidStream reads the rest of a solid entry after its head and returns the
// authenticated, decoded record stream with its stored (encoded) size. Like file
// entries, a failure past the metadata leaves the reader at the next entry.
func (se *SafeExtractor) readSolidStream(keys *archive.KeySchedule, head entryHead, decs *entryDecoders) ([]byte, int64, error) {
	if err := se.skipPadding(); err != nil {
		return nil, 0, recoverable(ErrCodeTruncated, "skip inter-block padding", err)
	}
	payload, err := se.decryptDataBlocks(head.fileKey, head.pm.SizeBucket, archive.CodecNone, nil)
	if err != nil {
		if isFatal(err) {
			return nil, 0, err
		}
		return nil, 0, se.skipTrailer(err)
	}
	trailer, err := se.readTrailer(head.fileKey, keys.Version())
	if err != nil {
		return nil, 0, err
	}

	stream := payload
	switch head.pm.Codec {
	case archive.CodecZstd:
		dec, err := decs.solidDecoder()
		if err != nil {
			return nil, 0, fatal(ErrCodeReadFailed, "init solid decompressor", err)
		}
		if stream, err = dec.Decompress(payload); err != nil {
			return nil, 0, recoverable(ErrCodeIntegrityFail, "decompress solid group", err)
		}
	default:
		if len(stream) > archive.MaxSolidStreamSize {
			return nil, 0, recoverable(ErrCodeIntegrityFail, "solid group exceeds maximum size", nil)
		}
	}
	if err := verifyPlaintext(head.fileKey, stream, trailer); err != nil {
		return nil, 0, err
	}
	return stream, int64(len(payload)), nil
}

// readSolidMembers reads and authenticates a solid group and parses its records.
func (se *SafeExtractor) readSolidMembers(keys *archive.KeySchedule, head entryHead, decs *entryDecoders) ([]archive.SolidMember, int64, int64, error) {
	stream, stored, err := se.readSolidStream(keys, head, decs)
	if err != nil {
		return nil, 0, 0, err
	}
	members, err := archive.ParseSolidStream(stream)
	if err != nil {
		return nil, 0, 0, recoverable(ErrCodeIntegrityFail, "parse solid group", err)
	}
	return members, int64(len(stream)), stored, nil
}

// extractSolidBody writes every member of an authenticated solid group into tree.
// The whole group is verified before any member is written.
func (se *SafeExtractor) extractSolidBody(keys *archive.KeySchedule, head entryHead, decs *entryDecoders, tree *outputTree) ([]ExtractionResult, error) {
	members, _, _, err := se.readSolidMembers(keys, head, decs)
	if err != nil {
		return nil, err
	}
	results := make([]ExtractionResult, 0, len(members))
	for _, m := range members {
		if err := tree.writeFile(m.Name, m.Data, &m.Attributes); err != nil {
			if isFatal(err) {
				return results, err
			}
			se.progress.FileError(m.Name, err)
			results = append(results, ExtractionResult{Filename: m.Name, Err: err})
			continue
		}
		se.progress.FileFinished(m.Name)
		results = append(results, ExtractionResult{Filename: m.Name, Size: int64(len(m.Data)), OK: true})
	}
	return results, nil
}

// listSolidBody returns one ListResult per member of an authenticated solid group.
func (se *SafeExtractor) listSolidBody(keys *archive.KeySchedule, head entryHead, decs *entryDecoders) ([]ListResult, error) {
	members, streamSize, stored, err := se.readSolidMembers(keys, head, decs)
	if err != nil {
		return nil, err
	}
	results := make([]ListResult, 0, len(members))
	for _, m := range members {
		size := int64(len(m.Data))
		results = append(results, withAttributes(ListResult{
			Filename:      m.Name,
			SizeBucket:    bucketName(archive.BucketizeSize(size)),
			Codec:         head.pm.Codec.String(),
			Solid:         true,
			OriginalBytes: size,
			StoredBytes:   size * stored / streamSize,
		}, &m.Attributes, 0))
	}
	return results, nil
}
