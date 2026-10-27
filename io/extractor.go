// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"filippo.io/age"

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
// OriginalBytes is the plaintext size; StoredBytes is the encoded payload size before
// encryption (equal to OriginalBytes for uncompressed entries).
// Solid members share one compressed stream, so their StoredBytes is their
// proportional share of the group's stored size.
type ListResult struct {
	Filename      string
	SizeBucket    string
	Codec         string
	Solid         bool
	OriginalBytes int64
	StoredBytes   int64
	Kind          archive.FileKind
	Mode          uint32 // permission and special bits, as in chmod
	LinkTarget    string // a symlink's target, or the entry a hard link points to
	ModTime       int64  // Unix nanoseconds; 0 when not recorded
	Err           error
}

// maxBlockCiphertext bounds a data block's on-disk ciphertext length before it is
// allocated, so a corrupt or hostile size field cannot force a huge allocation.
const maxBlockCiphertext = archive.MaxPayloadSize + crypto.GCMTagSize

// maxMetadataCiphertext bounds a sealed metadata block: a 64 KiB filename blob plus the
// fixed fields (see archive.marshalMetadata) and the GCM tag.
const maxMetadataCiphertext = archive.MaxMetadataSize + crypto.GCMTagSize

// isFatal reports whether err is a fatal ArchiveError, after which the entry stream
// cannot be parsed further.
func isFatal(err error) bool {
	var ae *ArchiveError
	return errors.As(err, &ae) && ae.IsFatal()
}

// errDecompress marks a block that authenticated but failed to decode.
var errDecompress = errors.New("io: block decompression failed")

// decompressingOpener decrypts a block and then zstd-decodes its payload.
type decompressingOpener struct {
	em  *crypto.EncryptionManager
	dec *archive.BlockDecompressor
}

func (o decompressingOpener) DecryptBlock(block crypto.EncryptedBlock) ([]byte, error) {
	payload, err := o.em.DecryptBlock(block)
	if err != nil {
		return nil, err
	}
	pt, err := o.dec.Decompress(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errDecompress, err)
	}
	return pt, nil
}

// entryHead is the opened prefix of a file or solid entry: everything up to and
// including its sealed metadata.
type entryHead struct {
	fileKey [crypto.KeySize]byte
	pm      archive.PlaintextMetadata
}

// entryDecoders holds the zstd decoders one Extract or List call needs. The solid
// decoder is created on first use, since most archives have no solid groups.
type entryDecoders struct {
	block *archive.BlockDecompressor
	solid *archive.BlockDecompressor
}

func (d *entryDecoders) solidDecoder() (*archive.BlockDecompressor, error) {
	if d.solid == nil {
		dec, err := archive.NewSolidDecompressor()
		if err != nil {
			return nil, err
		}
		d.solid = dec
	}
	return d.solid, nil
}

func (d *entryDecoders) close() {
	if d.block != nil {
		d.block.Close()
	}
	if d.solid != nil {
		d.solid.Close()
	}
}

// trailerInfo is the opened sealed trailer of one file entry.
type trailerInfo struct {
	hmac          [crypto.HMACSize]byte
	plaintextSize uint64
	hasSize       bool // false for Version1 trailers, which seal only the HMAC
}

// SafeExtractor decrypts and verifies files from a SARC archive.
type SafeExtractor struct {
	r          io.Reader
	password   string
	keyFiles   [][]byte
	identities []age.Identity
	progress   ProgressTracker
	header     headerInfo
	// restoreOwner restores recorded owners and setuid, setgid, and sticky bits.
	restoreOwner bool
	// random, when set, gives the random access incremental archives need; r reads the
	// same archive sequentially from its start.
	random     io.ReaderAt
	randomSize int64
}

// headerInfo is what readHeader learned beyond the key schedule (Version2+ only).
type headerInfo struct {
	flags             byte
	sealedCount       uint64 // file count, or session count for incremental archives
	recipientBlockLen int
}

// incremental reports whether the header marks an incremental archive.
func (h headerInfo) incremental() bool { return h.flags&archive.HeaderFlagIncremental != 0 }

// end returns the archive offset just past the Version2 header.
func (h headerInfo) end() int64 {
	return archive.FileCountOffset(h.recipientBlockLen) + archive.FileCountSealedSize + archive.ReservedSize
}

// NewSafeExtractor returns a SafeExtractor reading from r that unlocks the archive with
// password (empty for none), any key file added with WithKeyFiles, or any identity
// added with WithIdentities. Version1
// archives can only be opened with a password.
func NewSafeExtractor(r io.Reader, password string, progress ProgressTracker, opts ...ExtractorOption) *SafeExtractor {
	if progress == nil {
		progress = NopProgressTracker{}
	}
	se := &SafeExtractor{r: r, password: password, progress: progress}
	for _, opt := range opts {
		opt(se)
	}
	return se
}

// Extract decrypts every entry in the archive and writes its files under outputDir.
// Each entry is authenticated before any bytes are written to disk.
// Returns one ExtractionResult per file, including each member of a solid group, or
// one failed result for an entry that could not be opened.
//
// Every write goes through an os.Root on outputDir, so no entry, symlink, or hard link
// reaches outside it. Directory attributes are applied once all entries are written.
func (se *SafeExtractor) Extract(outputDir string) ([]ExtractionResult, error) {
	keys, err := se.readHeader()
	if err != nil {
		return nil, err
	}
	tree := newOutputTree(outputDir, se.restoreOwner, se.progress)
	defer tree.close()
	if se.header.incremental() {
		return se.extractIncremental(keys, tree)
	}
	block, err := archive.NewBlockDecompressor()
	if err != nil {
		return nil, fatal(ErrCodeReadFailed, "init decompressor", err)
	}
	decs := &entryDecoders{block: block}
	defer decs.close()

	var results []ExtractionResult
	for {
		entryType, more, err := se.nextEntryType(keys)
		if err != nil {
			return results, err
		}
		if !more {
			return results, nil
		}
		entryResults, err := se.extractEntry(keys, entryType, decs, tree)
		if err != nil {
			if isFatal(err) {
				return results, err
			}
			// Recoverable: the entry was consumed in full, so continue with the next one.
			results = append(results, ExtractionResult{Err: err})
			se.progress.FileError("unknown", err)
			continue
		}
		results = append(results, entryResults...)
	}
}

// readHeader parses the archive header and returns the KeySchedule matching its
// format version. For Version2 archives it unwraps the CEK from the recipient block
// with the extractor's password or identities, then confirms it on the sealed file count.
func (se *SafeExtractor) readHeader() (*archive.KeySchedule, error) {
	var magic [4]byte
	if _, err := io.ReadFull(se.r, magic[:]); err != nil {
		return nil, fatal(ErrCodeTruncated, "read magic", err)
	}
	if magic != archive.Magic {
		return nil, fatal(ErrCodeBadMagic, "invalid magic bytes", nil)
	}

	var version [2]byte
	if _, err := io.ReadFull(se.r, version[:]); err != nil {
		return nil, fatal(ErrCodeTruncated, "read version", err)
	}
	switch v := binary.LittleEndian.Uint16(version[:]); v {
	case archive.Version1:
		return se.readVersion1Header()
	case archive.Version2:
		return se.readVersion2Header()
	default:
		return nil, fatal(ErrCodeBadVersion, fmt.Sprintf("unsupported version %d", v), archive.ErrUnsupportedVersion)
	}
}

// readVersion1Header reads the rest of a Version1 header. Version1 seals its file count
// with a separate PBKDF2 key, so the password is only checked per entry.
func (se *SafeExtractor) readVersion1Header() (*archive.KeySchedule, error) {
	rest := make([]byte, crypto.SaltSize+archive.FileCountSealedSize+archive.ReservedSize)
	if _, err := io.ReadFull(se.r, rest); err != nil {
		return nil, fatal(ErrCodeTruncated, "read header", err)
	}
	if se.password == "" {
		return nil, fatal(ErrCodeAuthFailed, "version 1 archives require a password", nil)
	}
	return archive.NewVersion1KeySchedule(se.password), nil
}

// readVersion2Header reads the recipient block, unwraps the CEK, and authenticates the
// sealed file count with the derived header key before any entry is parsed.
func (se *SafeExtractor) readVersion2Header() (*archive.KeySchedule, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(se.r, lenBuf[:]); err != nil {
		return nil, fatal(ErrCodeTruncated, "read recipient block length", err)
	}
	blockLen := binary.LittleEndian.Uint32(lenBuf[:])
	if blockLen > archive.MaxRecipientBlockSize {
		return nil, fatal(ErrCodeIntegrityFail, "recipient block exceeds maximum size", nil)
	}
	block := make([]byte, blockLen)
	if _, err := io.ReadFull(se.r, block); err != nil {
		return nil, fatal(ErrCodeTruncated, "read recipient block", err)
	}
	var hdr archive.ArchiveHeader
	if _, err := io.ReadFull(se.r, hdr.FileCountEncrypted[:]); err != nil {
		return nil, fatal(ErrCodeTruncated, "read file count", err)
	}
	if _, err := io.ReadFull(se.r, hdr.Reserved[:]); err != nil {
		return nil, fatal(ErrCodeTruncated, "read header reserved", err)
	}

	cek, err := archive.OpenRecipientBlock(block, archive.Unlockers{
		Password: se.password, KeyFiles: se.keyFiles, Identities: se.identities,
	})
	var noMatch *archive.NoMatchingCredentialError
	if errors.As(err, &noMatch) {
		return nil, fatal(ErrCodeAuthFailed,
			"no matching credential; this archive accepts: "+strings.Join(noMatch.Accepts, ", "), err)
	}
	var identityErr *crypto.IdentityError
	if errors.As(err, &identityErr) {
		return nil, fatal(ErrCodeAuthFailed, "identity could not be used: "+identityErr.Err.Error(), err)
	}
	if err != nil {
		return nil, fatal(ErrCodeIntegrityFail, "malformed recipient block", err)
	}
	keys := archive.NewVersion2KeySchedule(cek)
	count, err := openFileCount(keys, hdr.FileCountEncrypted)
	if err != nil {
		return nil, fatal(ErrCodeAuthFailed, "corrupted header", err)
	}
	se.header = headerInfo{flags: hdr.Reserved[0], sealedCount: count, recipientBlockLen: int(blockLen)}
	return keys, nil
}

// openFileCount authenticates and returns the sealed header file count with the header
// key, confirming the recovered CEK and the header's integrity.
func openFileCount(keys *archive.KeySchedule, sealed [archive.FileCountSealedSize]byte) (uint64, error) {
	headerKey, err := keys.HeaderKey()
	if err != nil {
		return 0, err
	}
	em, err := crypto.NewEncryptionManager(headerKey)
	if err != nil {
		return 0, err
	}
	var nonce [crypto.NonceSize]byte
	copy(nonce[:], sealed[:crypto.NonceSize])
	plain, err := em.DecryptBlock(crypto.EncryptedBlock{Nonce: nonce, Ciphertext: sealed[crypto.NonceSize:]})
	if err != nil {
		return 0, err
	}
	if len(plain) != 8 {
		return 0, fmt.Errorf("sealed count is %d bytes", len(plain))
	}
	return binary.LittleEndian.Uint64(plain), nil
}

// nextEntryType reads the next entry type byte and reports whether an entry follows.
// Version2+ archives hold file and solid entries, possibly a directory and its locator,
// which are skipped, and end with EntryTypeEnd; EOF or any other byte is fatal.
// Version1 archives hold only file entries and have no end marker, so EOF or any byte
// other than EntryTypeFile ends them.
func (se *SafeExtractor) nextEntryType(keys *archive.KeySchedule) (byte, bool, error) {
	for {
		var b [1]byte
		_, err := io.ReadFull(se.r, b[:])
		if keys.Version() == archive.Version1 {
			if err == io.EOF {
				return 0, false, nil
			}
			if err != nil {
				return 0, false, fatal(ErrCodeTruncated, "read entry type", err)
			}
			return b[0], b[0] == archive.EntryTypeFile, nil
		}
		if err != nil {
			return 0, false, fatal(ErrCodeTruncated, "read entry type", err)
		}
		switch b[0] {
		case archive.EntryTypeFile, archive.EntryTypeSolid:
			return b[0], true, nil
		case archive.EntryTypeEnd:
			return b[0], false, nil
		case archive.EntryTypeDirectory, archive.EntryTypeDirectoryLocator:
			if err := se.skipDirectory(keys, b[0]); err != nil {
				return 0, false, err
			}
		default:
			return 0, false, fatal(ErrCodeIntegrityFail, fmt.Sprintf("unexpected entry type 0x%02x", b[0]), nil)
		}
	}
}

// readEntryHead reads an entry's salt, frame header, and sealed metadata, and opens the
// metadata. If the metadata fails to open, the rest of the entry is skipped so the
// reader stays aligned on the next one.
func (se *SafeExtractor) readEntryHead(keys *archive.KeySchedule) (entryHead, error) {
	var salt [crypto.SaltSize]byte
	if _, err := io.ReadFull(se.r, salt[:]); err != nil {
		return entryHead{}, recoverable(ErrCodeTruncated, "read entry salt", err)
	}
	fileKey, err := keys.FileKey(salt)
	if err != nil {
		return entryHead{}, fatal(ErrCodeAuthFailed, "derive file key", err)
	}
	if _, err := io.ReadFull(se.r, make([]byte, len(archive.FrameHeader{}))); err != nil {
		return entryHead{}, recoverable(ErrCodeTruncated, "read frame header", err)
	}
	metaBlock, err := se.readMetadataBlock()
	if err != nil {
		return entryHead{}, err
	}
	mm, err := archive.NewMetadataManager(fileKey)
	if err != nil {
		return entryHead{}, fatal(ErrCodeAuthFailed, "init metadata manager", err)
	}
	pm, err := mm.Open(metaBlock)
	if err != nil {
		return entryHead{}, se.skipEntryBody(recoverable(ErrCodeAuthFailed, "decrypt metadata", err))
	}
	return entryHead{fileKey: fileKey, pm: pm}, nil
}

// extractEntry extracts the entry whose type byte was just read.
func (se *SafeExtractor) extractEntry(keys *archive.KeySchedule, entryType byte, decs *entryDecoders, tree *outputTree) ([]ExtractionResult, error) {
	head, err := se.readEntryHead(keys)
	if err != nil {
		return nil, err
	}
	if entryType == archive.EntryTypeSolid {
		return se.extractSolidBody(keys, head, decs, tree)
	}
	result, err := se.extractFileBody(keys, head, decs.block, tree)
	if err != nil {
		return nil, err
	}
	return []ExtractionResult{result}, nil
}

// extractFileBody extracts the rest of a file entry after its head, streaming the
// plaintext into a hidden temporary file beside its destination while its HMAC and size are
// computed. Only after the trailer verifies is the file renamed to its final name, so
// unverified data never appears under it and memory stays constant for any file size.
func (se *SafeExtractor) extractFileBody(keys *archive.KeySchedule, head entryHead, dec *archive.BlockDecompressor, tree *outputTree) (ExtractionResult, error) {
	fileKey, pm := head.fileKey, head.pm
	filename, err := decryptFilename(pm.EncryptedFilename, fileKey)
	if err != nil {
		return ExtractionResult{}, se.skipEntryBody(recoverable(ErrCodeAuthFailed, "decrypt filename", err))
	}
	if pm.Attributes != nil && pm.Attributes.Kind != archive.KindRegular {
		return se.extractSpecial(tree, filename, pm.Attributes)
	}
	out, err := newVerifiedFile(tree, filename, fileKey)
	if err != nil {
		if isFatal(err) {
			return ExtractionResult{}, err
		}
		return ExtractionResult{}, se.skipEntryBody(err)
	}
	defer out.discard()

	if err := se.skipPadding(); err != nil {
		return ExtractionResult{}, recoverable(ErrCodeTruncated, "skip inter-block padding", err)
	}
	if err := se.streamDataBlocks(fileKey, pm.SizeBucket, pm.Codec, dec, out.write); err != nil {
		if isFatal(err) {
			return ExtractionResult{}, err
		}
		// Block framing is intact (the pipeline drains to the sentinel), so skip the
		// trailer and leave the reader at the next entry.
		return ExtractionResult{}, se.skipTrailer(err)
	}

	trailer, err := se.readTrailer(fileKey, keys.Version())
	if err != nil {
		return ExtractionResult{}, err
	}
	if err := out.verify(trailer); err != nil {
		return ExtractionResult{}, err
	}
	if err := out.publish(pm.Attributes, os.FileMode(pm.Permissions).Perm()); err != nil {
		return ExtractionResult{}, recoverable(ErrCodeWriteFailed, "write file", err)
	}

	se.progress.FileFinished(filename)
	return ExtractionResult{Filename: filename, Size: out.size, OK: true}, nil
}

// extractSpecial restores a directory, symlink, or hard link entry, whose body carries
// no data and is skipped.
func (se *SafeExtractor) extractSpecial(tree *outputTree, name string, attrs *archive.Attributes) (ExtractionResult, error) {
	if err := se.skipEntryBody(nil); err != nil {
		return ExtractionResult{}, err
	}
	if err := tree.special(name, attrs); err != nil {
		if isFatal(err) {
			return ExtractionResult{}, err
		}
		se.progress.FileError(name, err)
		return ExtractionResult{Filename: name, Err: err}, nil
	}
	se.progress.FileFinished(name)
	return ExtractionResult{Filename: name, OK: true}, nil
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
	size := binary.LittleEndian.Uint32(sizeBuf)
	if size > maxMetadataCiphertext {
		return archive.MetadataBlock{}, fatal(ErrCodeIntegrityFail, "metadata size exceeds maximum", nil)
	}
	ct := make([]byte, size)
	if _, err := io.ReadFull(se.r, ct); err != nil {
		return archive.MetadataBlock{}, recoverable(ErrCodeTruncated, "read metadata ciphertext", err)
	}
	return archive.MetadataBlock{Nonce: nonce, Ciphertext: ct}, nil
}

// skipEntryBody consumes the rest of an entry after its metadata block without any
// key, so a failure in one entry leaves the reader at the next. It returns cause, or
// the framing error that prevented the skip.
func (se *SafeExtractor) skipEntryBody(cause error) error {
	if err := se.skipPadding(); err != nil {
		return fatal(ErrCodeTruncated, "skip inter-block padding", err)
	}
	if _, err := se.skipDataBlocks(); err != nil {
		return err
	}
	return se.skipTrailer(cause)
}

// skipTrailer consumes a trailer without opening it and returns cause, or the framing
// error that prevented the skip.
func (se *SafeExtractor) skipTrailer(cause error) error {
	if err := se.skipPadding(); err != nil {
		return fatal(ErrCodeTruncated, "skip trailer padding", err)
	}
	header := make([]byte, crypto.NonceSize+4)
	if _, err := io.ReadFull(se.r, header); err != nil {
		return fatal(ErrCodeTruncated, "read sealed trailer header", err)
	}
	sealedSize := binary.LittleEndian.Uint32(header[crypto.NonceSize:])
	if sealedSize > archive.TrailerPayloadSize+crypto.GCMTagSize {
		return fatal(ErrCodeIntegrityFail, "sealed trailer too large", nil)
	}
	if _, err := io.CopyN(io.Discard, se.r, int64(sealedSize)+8); err != nil {
		return fatal(ErrCodeTruncated, "skip sealed trailer", err)
	}
	return cause
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

// decryptDataBlocks reads and authenticates a file's data blocks, decrypting them in
// parallel across up to GOMAXPROCS worker goroutines for entries large enough to
// benefit (BucketLarge/BucketHuge, i.e. > 100 KB). Block framing (nonce, size,
// ciphertext) is parsed sequentially since block boundaries can only be found by
// reading in order; the CPU-bound AES-256-GCM Open call for each block is what gets
// parallelised.
// CodecZstd payloads are decoded on the same worker right after decryption.
// Each block's plaintext is passed to sink in order; memory stays bounded by the
// pipeline depth regardless of file size.
func (se *SafeExtractor) streamDataBlocks(fileKey [crypto.KeySize]byte, bucket archive.SizeBucket, codec archive.Codec, dec *archive.BlockDecompressor, sink blockSink) error {
	em, err := crypto.NewEncryptionManager(fileKey)
	if err != nil {
		return fatal(ErrCodeAuthFailed, "init block decryptor", err)
	}
	var opener blockOpener = em
	if codec == archive.CodecZstd {
		opener = decompressingOpener{em: em, dec: dec}
	}

	var readErr error
	next := func() ([crypto.NonceSize]byte, []byte, bool, error) {
		var nonce [crypto.NonceSize]byte
		_, err := io.ReadFull(se.r, nonce[:])
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nonce, nil, false, nil
		}
		if err != nil {
			readErr = recoverable(ErrCodeTruncated, "read block nonce", err)
			return nonce, nil, false, readErr
		}

		sizeBuf := make([]byte, 4)
		if _, err := io.ReadFull(se.r, sizeBuf); err != nil {
			readErr = recoverable(ErrCodeTruncated, "read block size", err)
			return nonce, nil, false, readErr
		}
		blockSize := binary.LittleEndian.Uint32(sizeBuf)

		// Sentinel: a zero-length block marks the end of data blocks.
		if blockSize == 0 {
			return nonce, nil, false, nil
		}
		if blockSize > maxBlockCiphertext {
			readErr = fatal(ErrCodeIntegrityFail, "block size exceeds maximum", nil)
			return nonce, nil, false, readErr
		}

		ct := make([]byte, blockSize)
		if _, err := io.ReadFull(se.r, ct); err != nil {
			readErr = recoverable(ErrCodeTruncated, "read block ciphertext", err)
			return nonce, nil, false, readErr
		}
		return nonce, ct, true, nil
	}

	workers := 1
	if bucket >= archive.BucketLarge {
		if w := runtime.GOMAXPROCS(0); w > 1 {
			workers = w
		}
	}
	err = decryptBlocksParallel(opener, workers, next, sink)
	if err == nil {
		return nil
	}
	if readErr != nil {
		return readErr
	}
	var sinkErr *sinkError
	switch {
	case errors.As(err, &sinkErr):
		return recoverable(ErrCodeWriteFailed, "write file", err)
	case errors.Is(err, errDecompress):
		return recoverable(ErrCodeIntegrityFail, "decompress block", err)
	default:
		return recoverable(ErrCodeAuthFailed, "decrypt block", err)
	}
}

// decryptDataBlocks is streamDataBlocks collecting the plaintext in memory, for
// payloads with a small fixed bound such as solid groups.
func (se *SafeExtractor) decryptDataBlocks(fileKey [crypto.KeySize]byte, bucket archive.SizeBucket, codec archive.Codec, dec *archive.BlockDecompressor) ([]byte, error) {
	var out bytes.Buffer
	err := se.streamDataBlocks(fileKey, bucket, codec, dec, func(pt []byte) error {
		_, werr := out.Write(pt)
		return werr
	})
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// skipDataBlocks consumes a file's data blocks through the sentinel without decrypting
// them and returns the total encoded payload size (ciphertext minus GCM tags).
func (se *SafeExtractor) skipDataBlocks() (int64, error) {
	var stored int64
	header := make([]byte, crypto.NonceSize+4)
	for {
		if _, err := io.ReadFull(se.r, header); err != nil {
			return 0, recoverable(ErrCodeTruncated, "read block header", err)
		}
		blockSize := binary.LittleEndian.Uint32(header[crypto.NonceSize:])
		if blockSize == 0 {
			return stored, nil
		}
		if blockSize > maxBlockCiphertext || blockSize < crypto.GCMTagSize {
			return 0, fatal(ErrCodeIntegrityFail, "block size out of range", nil)
		}
		if _, err := io.CopyN(io.Discard, se.r, int64(blockSize)); err != nil {
			return 0, recoverable(ErrCodeTruncated, "skip block ciphertext", err)
		}
		stored += int64(blockSize) - crypto.GCMTagSize
	}
}

// readTrailer consumes a file trailer and opens its sealed payload without verifying
// it against any plaintext. Version2+ payloads also carry the plaintext size.
func (se *SafeExtractor) readTrailer(fileKey [crypto.KeySize]byte, version uint16) (trailerInfo, error) {
	if err := se.skipPadding(); err != nil {
		return trailerInfo{}, recoverable(ErrCodeTruncated, "skip trailer padding", err)
	}

	var sealedNonce [crypto.NonceSize]byte
	if _, err := io.ReadFull(se.r, sealedNonce[:]); err != nil {
		return trailerInfo{}, recoverable(ErrCodeTruncated, "read HMAC nonce", err)
	}
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(se.r, sizeBuf); err != nil {
		return trailerInfo{}, recoverable(ErrCodeTruncated, "read HMAC sealed size", err)
	}
	sealedSize := binary.LittleEndian.Uint32(sizeBuf)
	if sealedSize > archive.TrailerPayloadSize+crypto.GCMTagSize {
		return trailerInfo{}, fatal(ErrCodeIntegrityFail, "sealed trailer too large", nil)
	}
	sealed := make([]byte, sealedSize)
	if _, err := io.ReadFull(se.r, sealed); err != nil {
		return trailerInfo{}, recoverable(ErrCodeTruncated, "read HMAC sealed", err)
	}

	// Consume the entry checksum (8 bytes, boundary detection only) before any
	// verification so a failed check still leaves the reader at the next entry.
	if _, err := io.ReadFull(se.r, make([]byte, 8)); err != nil {
		return trailerInfo{}, recoverable(ErrCodeTruncated, "read entry checksum", err)
	}

	em, err := crypto.NewEncryptionManager(fileKey)
	if err != nil {
		return trailerInfo{}, fatal(ErrCodeAuthFailed, "init HMAC decryptor", err)
	}
	payload, err := em.DecryptBlock(crypto.EncryptedBlock{Nonce: sealedNonce, Ciphertext: sealed})
	if err != nil {
		return trailerInfo{}, recoverable(ErrCodeAuthFailed, "decrypt HMAC", err)
	}

	var info trailerInfo
	switch {
	case version == archive.Version1 && len(payload) == crypto.HMACSize:
	case version != archive.Version1 && len(payload) == archive.TrailerPayloadSize:
		info.plaintextSize = binary.LittleEndian.Uint64(payload[crypto.HMACSize:])
		info.hasSize = true
	default:
		return trailerInfo{}, recoverable(ErrCodeIntegrityFail, "HMAC length mismatch", nil)
	}
	copy(info.hmac[:], payload[:crypto.HMACSize])
	return info, nil
}

// verifyPlaintext checks the decoded plaintext against the trailer's HMAC and, when
// present, its recorded size.
func verifyPlaintext(fileKey [crypto.KeySize]byte, plaintext []byte, trailer trailerInfo) error {
	if err := crypto.VerifyHMAC(fileKey, plaintext, trailer.hmac); err != nil {
		return recoverable(ErrCodeIntegrityFail, "plaintext HMAC mismatch", err)
	}
	if trailer.hasSize && trailer.plaintextSize != uint64(len(plaintext)) {
		return recoverable(ErrCodeIntegrityFail, "plaintext size mismatch", nil)
	}
	return nil
}

// List decrypts metadata for every entry and returns a ListResult per file, including
// each member of a solid group. Data blocks of file entries are never decrypted; solid
// groups are decrypted in memory to read their member records. Nothing is written to disk.
//
// With random access (WithRandomAccess), the header and any directory are read through
// it, so listing an archive with a directory reads no data block; the sequential reader
// is used only to scan an archive without one.
func (se *SafeExtractor) List() ([]ListResult, error) {
	if se.random != nil {
		return se.listRandom()
	}
	keys, err := se.readHeader()
	if err != nil {
		return nil, err
	}
	if se.header.incremental() {
		return se.listIncremental(keys)
	}
	return se.scanList(keys)
}

// listRandom lists through random access: an incremental archive through its session
// indexes, a one-pass archive through its directory, and one without a directory by
// scanning the sequential reader after skipping the header read through random access.
func (se *SafeExtractor) listRandom() ([]ListResult, error) {
	stream := se.r
	counter := &byteCounter{r: bufio.NewReaderSize(io.NewSectionReader(se.random, 0, se.randomSize), entryReadBufferSize)}
	se.r = counter
	keys, err := se.readHeader()
	se.r = stream
	if err != nil {
		return nil, err
	}
	if se.header.incremental() {
		return se.listIncremental(keys)
	}
	if keys.Version() != archive.Version1 {
		records, ok, err := readDirectory(se.random, se.randomSize, keys, se.header)
		if err != nil {
			return nil, err
		}
		if ok {
			return directoryListing(records), nil
		}
	}
	if _, err := io.CopyN(io.Discard, se.r, counter.n); err != nil {
		return nil, fatal(ErrCodeTruncated, "read header", err)
	}
	return se.scanList(keys)
}

// scanList lists every entry after the header by reading the archive sequentially.
func (se *SafeExtractor) scanList(keys *archive.KeySchedule) ([]ListResult, error) {
	decs := &entryDecoders{}
	defer decs.close()

	var results []ListResult
	for {
		entryType, more, err := se.nextEntryType(keys)
		if err != nil {
			return results, err
		}
		if !more {
			return results, nil
		}
		entryResults, err := se.listEntry(keys, entryType, decs)
		if err != nil {
			if isFatal(err) {
				return results, err
			}
			results = append(results, ListResult{Filename: "<decrypt error>", SizeBucket: "?", Codec: "?", Err: err})
			continue
		}
		results = append(results, entryResults...)
	}
}

// listEntry lists the entry whose type byte was just read.
func (se *SafeExtractor) listEntry(keys *archive.KeySchedule, entryType byte, decs *entryDecoders) ([]ListResult, error) {
	head, err := se.readEntryHead(keys)
	if err != nil {
		return nil, err
	}
	if entryType == archive.EntryTypeSolid {
		return se.listSolidBody(keys, head, decs)
	}
	result, err := se.listFileBody(keys, head)
	if err != nil {
		return nil, err
	}
	return []ListResult{result}, nil
}

// listFileBody reads the rest of a file entry after its head without decrypting its
// data blocks.
func (se *SafeExtractor) listFileBody(keys *archive.KeySchedule, head entryHead) (ListResult, error) {
	fileKey, pm := head.fileKey, head.pm
	filename, err := decryptFilename(pm.EncryptedFilename, fileKey)
	if err != nil {
		return ListResult{}, se.skipEntryBody(recoverable(ErrCodeAuthFailed, "decrypt filename", err))
	}

	// Data blocks are skipped by their length prefixes, never decrypted: list needs only
	// metadata and the trailer's recorded size.
	if err := se.skipPadding(); err != nil {
		return ListResult{}, recoverable(ErrCodeTruncated, "skip inter-block padding", err)
	}
	stored, err := se.skipDataBlocks()
	if err != nil {
		return ListResult{}, err
	}
	trailer, err := se.readTrailer(fileKey, keys.Version())
	if err != nil {
		return ListResult{}, err
	}
	original := stored // Version1 entries are never compressed
	if trailer.hasSize {
		original = int64(trailer.plaintextSize)
	}

	return withAttributes(ListResult{
		Filename:      filename,
		SizeBucket:    bucketName(pm.SizeBucket),
		Codec:         pm.Codec.String(),
		OriginalBytes: original,
		StoredBytes:   stored,
	}, pm.Attributes, pm.Permissions), nil
}

// withAttributes fills a listing's kind, mode, and link target from attrs, or from the
// legacy permissions when an entry has no attributes.
func withAttributes(r ListResult, attrs *archive.Attributes, permissions uint32) ListResult {
	if attrs == nil {
		r.Mode = permissions & 0o777
		return r
	}
	r.Kind, r.Mode, r.LinkTarget = attrs.Kind, attrs.Mode, attrs.LinkTarget
	r.ModTime = attrs.ModTime
	return r
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
