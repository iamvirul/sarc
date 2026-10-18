// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

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
	Err           error
}

// maxBlockCiphertext bounds a data block's on-disk ciphertext length before it is
// allocated, so a corrupt or hostile size field cannot force a huge allocation.
const maxBlockCiphertext = archive.MaxPayloadSize + crypto.GCMTagSize

// maxMetadataCiphertext bounds a sealed metadata block: a 64 KiB filename blob plus the
// fixed fields (see archive.marshalMetadata) and the GCM tag.
const maxMetadataCiphertext = 2 + 0xFFFF + 1 + 32 + 4 + 1 + crypto.GCMTagSize

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
	r        io.Reader
	password string
	progress ProgressTracker
}

// NewSafeExtractor returns a SafeExtractor reading from r.
func NewSafeExtractor(r io.Reader, password string, progress ProgressTracker) *SafeExtractor {
	if progress == nil {
		progress = NopProgressTracker{}
	}
	return &SafeExtractor{r: r, password: password, progress: progress}
}

// Extract decrypts every entry in the archive and writes its files under outputDir.
// Each entry is authenticated before any bytes are written to disk.
// Returns one ExtractionResult per file, including each member of a solid group, or
// one failed result for an entry that could not be opened.
func (se *SafeExtractor) Extract(outputDir string) ([]ExtractionResult, error) {
	keys, err := se.readHeader()
	if err != nil {
		return nil, err
	}
	block, err := archive.NewBlockDecompressor()
	if err != nil {
		return nil, fatal(ErrCodeReadFailed, "init decompressor", err)
	}
	decs := &entryDecoders{block: block}
	defer decs.close()

	var results []ExtractionResult
	for {
		entryType, more, err := se.nextEntryType(keys.Version())
		if err != nil {
			return results, err
		}
		if !more {
			return results, nil
		}
		entryResults, err := se.extractEntry(keys, entryType, decs, outputDir)
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
// format version. For Version2 archives this runs the archive's single PBKDF2.
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
	v := binary.LittleEndian.Uint16(version[:])

	var hdr archive.ArchiveHeader
	if _, err := io.ReadFull(se.r, hdr.ArchiveSalt[:]); err != nil {
		return nil, fatal(ErrCodeTruncated, "read archive salt", err)
	}
	if _, err := io.ReadFull(se.r, hdr.FileCountEncrypted[:]); err != nil {
		return nil, fatal(ErrCodeTruncated, "read file count", err)
	}
	if _, err := io.ReadFull(se.r, hdr.Reserved[:]); err != nil {
		return nil, fatal(ErrCodeTruncated, "read header reserved", err)
	}

	keys, err := archive.NewKeySchedule(se.password, v, hdr.ArchiveSalt)
	if errors.Is(err, archive.ErrUnsupportedVersion) {
		return nil, fatal(ErrCodeBadVersion, fmt.Sprintf("unsupported version %d", v), err)
	}
	if err != nil {
		return nil, fatal(ErrCodeAuthFailed, "init key schedule", err)
	}
	if v != archive.Version1 {
		if err := openFileCount(keys, hdr.FileCountEncrypted); err != nil {
			return nil, fatal(ErrCodeAuthFailed, "wrong password or corrupted header", err)
		}
	}
	return keys, nil
}

// openFileCount authenticates the sealed header file count with the header key,
// rejecting a wrong password before any entry is parsed. Version1 archives seal it
// with a separate PBKDF2 key, so they skip this check to avoid an extra PBKDF2 run.
func openFileCount(keys *archive.KeySchedule, sealed [8 + crypto.NonceSize + crypto.GCMTagSize]byte) error {
	headerKey, err := keys.HeaderKey()
	if err != nil {
		return err
	}
	em, err := crypto.NewEncryptionManager(headerKey)
	if err != nil {
		return err
	}
	var nonce [crypto.NonceSize]byte
	copy(nonce[:], sealed[:crypto.NonceSize])
	_, err = em.DecryptBlock(crypto.EncryptedBlock{Nonce: nonce, Ciphertext: sealed[crypto.NonceSize:]})
	return err
}

// nextEntryType reads the next entry type byte and reports whether an entry follows.
// Version2+ archives hold file and solid entries and end with EntryTypeEnd; EOF or any
// other byte is fatal. Version1 archives hold only file entries and have no end marker,
// so EOF or any byte other than EntryTypeFile ends them.
func (se *SafeExtractor) nextEntryType(version uint16) (byte, bool, error) {
	var b [1]byte
	_, err := io.ReadFull(se.r, b[:])
	if version == archive.Version1 {
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
	default:
		return 0, false, fatal(ErrCodeIntegrityFail, fmt.Sprintf("unexpected entry type 0x%02x", b[0]), nil)
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
func (se *SafeExtractor) extractEntry(keys *archive.KeySchedule, entryType byte, decs *entryDecoders, outputDir string) ([]ExtractionResult, error) {
	head, err := se.readEntryHead(keys)
	if err != nil {
		return nil, err
	}
	if entryType == archive.EntryTypeSolid {
		return se.extractSolidBody(keys, head, decs, outputDir)
	}
	result, err := se.extractFileBody(keys, head, decs.block, outputDir)
	if err != nil {
		return nil, err
	}
	return []ExtractionResult{result}, nil
}

// extractFileBody extracts the rest of a file entry after its head.
func (se *SafeExtractor) extractFileBody(keys *archive.KeySchedule, head entryHead, dec *archive.BlockDecompressor, outputDir string) (ExtractionResult, error) {
	fileKey, pm := head.fileKey, head.pm
	filename, err := decryptFilename(pm.EncryptedFilename, fileKey)
	if err != nil {
		return ExtractionResult{}, se.skipEntryBody(recoverable(ErrCodeAuthFailed, "decrypt filename", err))
	}

	if err := se.skipPadding(); err != nil {
		return ExtractionResult{}, recoverable(ErrCodeTruncated, "skip inter-block padding", err)
	}

	plaintext, err := se.decryptDataBlocks(fileKey, pm.SizeBucket, pm.Codec, dec)
	if err != nil {
		if isFatal(err) {
			return ExtractionResult{}, err
		}
		// Block framing is intact (decryptDataBlocks drains to the sentinel), so skip
		// the trailer and leave the reader at the next entry.
		return ExtractionResult{}, se.skipTrailer(err)
	}

	trailer, err := se.readTrailer(fileKey, keys.Version())
	if err != nil {
		return ExtractionResult{}, err
	}
	if err := verifyPlaintext(fileKey, plaintext, trailer); err != nil {
		return ExtractionResult{}, err
	}

	outPath := filepath.Join(outputDir, filepath.Base(filename))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return ExtractionResult{}, fatal(ErrCodeWriteFailed, "create output dir", err)
	}
	if err := os.WriteFile(outPath, plaintext, os.FileMode(pm.Permissions)); err != nil {
		return ExtractionResult{}, recoverable(ErrCodeWriteFailed, "write file", err)
	}

	se.progress.FileFinished(filename)
	return ExtractionResult{Filename: filename, Size: int64(len(plaintext)), OK: true}, nil
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
func (se *SafeExtractor) decryptDataBlocks(fileKey [crypto.KeySize]byte, bucket archive.SizeBucket, codec archive.Codec, dec *archive.BlockDecompressor) ([]byte, error) {
	em, err := crypto.NewEncryptionManager(fileKey)
	if err != nil {
		return nil, fatal(ErrCodeAuthFailed, "init block decryptor", err)
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
	plaintext, err := decryptBlocksParallel(opener, workers, next)
	if err != nil {
		if readErr != nil {
			return nil, readErr
		}
		if errors.Is(err, errDecompress) {
			return nil, recoverable(ErrCodeIntegrityFail, "decompress block", err)
		}
		return nil, recoverable(ErrCodeAuthFailed, "decrypt block", err)
	}
	return plaintext, nil
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
func (se *SafeExtractor) List() ([]ListResult, error) {
	keys, err := se.readHeader()
	if err != nil {
		return nil, err
	}

	decs := &entryDecoders{}
	defer decs.close()

	var results []ListResult
	for {
		entryType, more, err := se.nextEntryType(keys.Version())
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

	return ListResult{
		Filename:      filename,
		SizeBucket:    bucketName(pm.SizeBucket),
		Codec:         pm.Codec.String(),
		OriginalBytes: original,
		StoredBytes:   stored,
	}, nil
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
