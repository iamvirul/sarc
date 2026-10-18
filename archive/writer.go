// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"github.com/iamvirul/sarc/crypto"
)

// writeBufferSize is the size of the userspace write buffer wrapping the output sink.
// Batching writes into 4 MB chunks reduces OS write syscalls from O(blocks) to O(MB/4).
const writeBufferSize = 4 * 1024 * 1024

// ArchiveWriter serialises a SARC archive to an io.Writer.
// Writes are buffered through a 4 MB bufio.Writer to batch OS syscalls.
// A MultiWriter tees every buffered write into a running SHA-256 for the footer HMAC.
type ArchiveWriter struct {
	w      io.Writer     // points to bw; footer writes bypass tee but still go here
	bw     *bufio.Writer // flushed once in WriteFooter
	hasher hash.Hash
	tee    io.Writer // MultiWriter(bw, hasher) — all archive content goes through this
	keys   *KeySchedule
}

// NewArchiveWriter returns an ArchiveWriter that writes a Version archive to w.
// archiveSalt must be generated before calling this and embedded in the header.
// The password is stretched with PBKDF2 exactly once here; per-file keys are then
// derived from the resulting master key with HKDF.
func NewArchiveWriter(w io.Writer, password string, archiveSalt [crypto.SaltSize]byte) (*ArchiveWriter, error) {
	keys, err := NewKeySchedule(password, Version, archiveSalt)
	if err != nil {
		return nil, fmt.Errorf("archive/writer: key schedule: %w", err)
	}
	bw := bufio.NewWriterSize(w, writeBufferSize)
	hasher := sha256.New()
	return &ArchiveWriter{
		w:      bw,
		bw:     bw,
		hasher: hasher,
		tee:    io.MultiWriter(bw, hasher),
		keys:   keys,
	}, nil
}

// WriteHeader serialises and writes the ArchiveHeader.
// hdr.Version must equal Version. fileCount is sealed with the header key before embedding.
func (aw *ArchiveWriter) WriteHeader(hdr ArchiveHeader, fileCount uint64) error {
	if hdr.Version != aw.keys.Version() {
		return fmt.Errorf("archive/writer: header version %d does not match writer version %d: %w",
			hdr.Version, aw.keys.Version(), ErrUnsupportedVersion)
	}
	headerKey, err := aw.keys.HeaderKey()
	if err != nil {
		return fmt.Errorf("archive/writer: header key: %w", err)
	}
	em, err := crypto.NewEncryptionManager(headerKey)
	if err != nil {
		return fmt.Errorf("archive/writer: header encryption: %w", err)
	}
	var countBuf [8]byte
	binary.LittleEndian.PutUint64(countBuf[:], fileCount)
	sealed, err := em.EncryptBlock(countBuf[:])
	if err != nil {
		return fmt.Errorf("archive/writer: seal file count: %w", err)
	}
	copy(hdr.FileCountEncrypted[:crypto.NonceSize], sealed.Nonce[:])
	copy(hdr.FileCountEncrypted[crypto.NonceSize:], sealed.Ciphertext)
	return aw.writeHeader(hdr)
}

// WriteFileEntry serialises a complete FileEntry to the stream.
func (aw *ArchiveWriter) WriteFileEntry(entry FileEntry) error {
	if err := writeByte(aw.tee, entry.EntryType); err != nil {
		return fmt.Errorf("archive/writer: entry type: %w", err)
	}
	if _, err := aw.tee.Write(entry.EntrySalt[:]); err != nil {
		return fmt.Errorf("archive/writer: entry salt: %w", err)
	}
	if _, err := aw.tee.Write(entry.FrameHdr[:]); err != nil {
		return fmt.Errorf("archive/writer: frame header: %w", err)
	}
	if err := aw.writeMetadataBlock(entry.Metadata); err != nil {
		return err
	}
	if err := aw.writePadding(entry.InterBlockPad); err != nil {
		return fmt.Errorf("archive/writer: inter-block padding: %w", err)
	}
	for i, db := range entry.DataBlocks {
		if err := aw.writeDataBlock(db); err != nil {
			return fmt.Errorf("archive/writer: data block %d: %w", i, err)
		}
	}
	// Sentinel: 12-byte zero nonce + 4-byte zero size signals end of data blocks to extractor.
	if _, err := aw.tee.Write(make([]byte, crypto.NonceSize+4)); err != nil {
		return fmt.Errorf("archive/writer: data block sentinel: %w", err)
	}
	return aw.writeTrailer(entry.Trailer)
}

// BeginFileEntry writes all fields of a file entry up to (but not including) data blocks.
// Follow with one AppendDataBlock call per encrypted chunk, then EndFileEntry.
func (aw *ArchiveWriter) BeginFileEntry(entryType byte, salt [crypto.SaltSize]byte, frameHdr FrameHeader, meta MetadataBlock, interPad []byte) error {
	if err := writeByte(aw.tee, entryType); err != nil {
		return fmt.Errorf("archive/writer: entry type: %w", err)
	}
	if _, err := aw.tee.Write(salt[:]); err != nil {
		return fmt.Errorf("archive/writer: entry salt: %w", err)
	}
	if _, err := aw.tee.Write(frameHdr[:]); err != nil {
		return fmt.Errorf("archive/writer: frame header: %w", err)
	}
	if err := aw.writeMetadataBlock(meta); err != nil {
		return err
	}
	return aw.writePadding(interPad)
}

// AppendDataBlock writes one encrypted data block to the stream.
func (aw *ArchiveWriter) AppendDataBlock(db DataBlock) error {
	return aw.writeDataBlock(db)
}

// EndFileEntry writes the data-block sentinel and the file trailer.
// Must be called exactly once after all AppendDataBlock calls for a file.
func (aw *ArchiveWriter) EndFileEntry(trailer FileTrailer) error {
	if _, err := aw.tee.Write(make([]byte, crypto.NonceSize+4)); err != nil {
		return fmt.Errorf("archive/writer: data block sentinel: %w", err)
	}
	return aw.writeTrailer(trailer)
}

// WriteFooter writes the EntryTypeEnd marker, computes the archive HMAC over everything
// up to and including the marker, writes the footer, and flushes the buffer.
// No further writes must occur after this call.
func (aw *ArchiveWriter) WriteFooter() error {
	if err := writeByte(aw.tee, EntryTypeEnd); err != nil {
		return fmt.Errorf("archive/writer: end marker: %w", err)
	}
	var footer ArchiveFooter
	copy(footer.ArchiveHMAC[:], aw.hasher.Sum(nil))
	// Footer bytes go to aw.w (bufio), not aw.tee — footer must not feed the hasher.
	if _, err := aw.w.Write(footer.ArchiveHMAC[:]); err != nil {
		return fmt.Errorf("archive/writer: footer HMAC: %w", err)
	}
	reserved := make([]byte, ReservedSize)
	if _, err := aw.w.Write(reserved); err != nil {
		return fmt.Errorf("archive/writer: footer reserved: %w", err)
	}
	return aw.bw.Flush()
}

// DeriveFileKey derives the per-file AES-256 key for salt from the archive master key.
// Safe for concurrent use.
func (aw *ArchiveWriter) DeriveFileKey(salt [crypto.SaltSize]byte) ([crypto.KeySize]byte, error) {
	return aw.keys.FileKey(salt)
}

func (aw *ArchiveWriter) writeHeader(hdr ArchiveHeader) error {
	var buf bytes.Buffer
	buf.Write(hdr.Magic[:])
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, hdr.Version)
	buf.Write(b)
	buf.Write(hdr.ArchiveSalt[:])
	buf.Write(hdr.FileCountEncrypted[:])
	buf.Write(hdr.Reserved[:])
	if _, err := aw.tee.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("archive/writer: write header: %w", err)
	}
	return nil
}

func (aw *ArchiveWriter) writeMetadataBlock(mb MetadataBlock) error {
	if _, err := aw.tee.Write(mb.Nonce[:]); err != nil {
		return fmt.Errorf("archive/writer: metadata nonce: %w", err)
	}
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(mb.Ciphertext)))
	if _, err := aw.tee.Write(size); err != nil {
		return fmt.Errorf("archive/writer: metadata size: %w", err)
	}
	if _, err := aw.tee.Write(mb.Ciphertext); err != nil {
		return fmt.Errorf("archive/writer: metadata ciphertext: %w", err)
	}
	return nil
}

func (aw *ArchiveWriter) writePadding(pad []byte) error {
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(pad)))
	if _, err := aw.tee.Write(size); err != nil {
		return err
	}
	_, err := aw.tee.Write(pad)
	return err
}

func (aw *ArchiveWriter) writeDataBlock(db DataBlock) error {
	if _, err := aw.tee.Write(db.Nonce[:]); err != nil {
		return fmt.Errorf("archive/writer: block nonce: %w", err)
	}
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(db.Ciphertext)))
	if _, err := aw.tee.Write(size); err != nil {
		return fmt.Errorf("archive/writer: block size: %w", err)
	}
	if _, err := aw.tee.Write(db.Ciphertext); err != nil {
		return fmt.Errorf("archive/writer: block ciphertext: %w", err)
	}
	return nil
}

func (aw *ArchiveWriter) writeTrailer(t FileTrailer) error {
	if err := aw.writePadding(t.RandomPadding); err != nil {
		return fmt.Errorf("archive/writer: trailer padding: %w", err)
	}
	if _, err := aw.tee.Write(t.PlaintextHMACNonce[:]); err != nil {
		return fmt.Errorf("archive/writer: HMAC nonce: %w", err)
	}
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(t.PlaintextHMACSealed)))
	if _, err := aw.tee.Write(size); err != nil {
		return fmt.Errorf("archive/writer: HMAC sealed size: %w", err)
	}
	if _, err := aw.tee.Write(t.PlaintextHMACSealed); err != nil {
		return fmt.Errorf("archive/writer: HMAC sealed: %w", err)
	}
	if _, err := aw.tee.Write(t.EntryChecksum[:]); err != nil {
		return fmt.Errorf("archive/writer: entry checksum: %w", err)
	}
	return nil
}

func writeByte(w io.Writer, b byte) error {
	_, err := w.Write([]byte{b})
	return err
}
