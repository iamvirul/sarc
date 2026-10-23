// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
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
	hasher *ArchiveChecksum
	tee    io.Writer // MultiWriter(bw, hasher, counter): all archive content goes through this
	offset *offsetCounter
	keys   *KeySchedule
	// recipients is the sealed recipient block written into the header.
	recipients []byte
}

// NewArchiveWriter returns an ArchiveWriter that writes a Version archive to w, openable
// by any one of creds. It generates a random CEK, wraps it for every credential, and
// derives all file keys from the CEK with HKDF.
func NewArchiveWriter(w io.Writer, creds Credentials) (*ArchiveWriter, error) {
	cek, err := crypto.GenerateCEK()
	if err != nil {
		return nil, fmt.Errorf("archive/writer: %w", err)
	}
	recipients, err := SealRecipientBlock(cek, creds)
	if err != nil {
		return nil, fmt.Errorf("archive/writer: %w", err)
	}
	return newArchiveWriter(w, NewVersion2KeySchedule(cek), recipients, NewArchiveChecksum(), 0), nil
}

// ResumeArchiveWriter returns an ArchiveWriter that appends to an existing archive at
// offset, where w is positioned. hashState is the marshaled SHA-256 state of the
// archive's first offset bytes (from a Checkpoint), so the footer checksum covers the
// whole archive without rereading it. No header is written.
func ResumeArchiveWriter(w io.Writer, keys *KeySchedule, offset int64, hashState []byte) (*ArchiveWriter, error) {
	hasher, err := ResumeArchiveChecksum(hashState)
	if err != nil {
		return nil, fmt.Errorf("archive/writer: %w", err)
	}
	return newArchiveWriter(w, keys, nil, hasher, offset), nil
}

func newArchiveWriter(w io.Writer, keys *KeySchedule, recipients []byte, hasher *ArchiveChecksum, offset int64) *ArchiveWriter {
	bw := bufio.NewWriterSize(w, writeBufferSize)
	counter := &offsetCounter{n: offset}
	return &ArchiveWriter{
		w:          bw,
		bw:         bw,
		hasher:     hasher,
		tee:        io.MultiWriter(bw, hasher, counter),
		offset:     counter,
		keys:       keys,
		recipients: recipients,
	}
}

// offsetCounter counts the archive bytes written so far.
type offsetCounter struct{ n int64 }

func (c *offsetCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// Offset returns the archive offset of the next byte to be written.
func (aw *ArchiveWriter) Offset() int64 { return aw.offset.n }

// Keys returns the writer's key schedule.
func (aw *ArchiveWriter) Keys() *KeySchedule { return aw.keys }

// WriteHeader serialises and writes the archive header, sealing fileCount with the
// header key. It must be called once, before any entry.
func (aw *ArchiveWriter) WriteHeader(fileCount uint64) error {
	return aw.WriteHeaderWithFlags(fileCount, 0)
}

// WriteHeaderWithFlags is WriteHeader with flags (such as HeaderFlagIncremental) stored
// in the first reserved header byte.
func (aw *ArchiveWriter) WriteHeaderWithFlags(fileCount uint64, flags byte) error {
	hdr := ArchiveHeader{Magic: Magic, Version: aw.keys.Version(), RecipientBlock: aw.recipients}
	sealed, err := SealFileCount(aw.keys, fileCount)
	if err != nil {
		return err
	}
	hdr.FileCountEncrypted = sealed
	hdr.Reserved[0] = flags
	return aw.writeHeader(hdr)
}

// FileCountOffset returns the archive offset of the sealed file count in a Version2
// header with this writer's recipient block, for rewriting it in place.
func (aw *ArchiveWriter) FileCountOffset() int64 {
	return FileCountOffset(len(aw.recipients))
}

// FileCountOffset returns the offset of the sealed file count in a Version2 header
// whose recipient block is recipientBlockLen bytes.
func FileCountOffset(recipientBlockLen int) int64 {
	return int64(len(Magic) + 2 + 4 + recipientBlockLen)
}

// SealFileCount seals count with keys' header key, as stored in the header.
func SealFileCount(keys *KeySchedule, count uint64) ([FileCountSealedSize]byte, error) {
	var out [FileCountSealedSize]byte
	headerKey, err := keys.HeaderKey()
	if err != nil {
		return out, fmt.Errorf("archive/writer: header key: %w", err)
	}
	em, err := crypto.NewEncryptionManager(headerKey)
	if err != nil {
		return out, fmt.Errorf("archive/writer: header encryption: %w", err)
	}
	var countBuf [8]byte
	binary.LittleEndian.PutUint64(countBuf[:], count)
	sealed, err := em.EncryptBlock(countBuf[:])
	if err != nil {
		return out, fmt.Errorf("archive/writer: seal file count: %w", err)
	}
	copy(out[:crypto.NonceSize], sealed.Nonce[:])
	copy(out[crypto.NonceSize:], sealed.Ciphertext)
	return out, nil
}

// WriteCheckpointFooter ends an incremental archive: a checkpoint pointing at the
// session index at lastIndex and carrying the checksum state so far, then the end
// marker and footer (see WriteFooter).
func (aw *ArchiveWriter) WriteCheckpointFooter(lastIndex int64) error {
	state, err := aw.hasher.MarshalBinary()
	if err != nil {
		return fmt.Errorf("archive/writer: save checksum state: %w", err)
	}
	cp, err := Checkpoint{LastIndex: uint64(lastIndex), HashState: state}.Marshal()
	if err != nil {
		return err
	}
	if _, err := aw.tee.Write(cp); err != nil {
		return fmt.Errorf("archive/writer: checkpoint: %w", err)
	}
	return aw.WriteFooter()
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
	b = binary.LittleEndian.AppendUint32(b[:0], uint32(len(hdr.RecipientBlock)))
	buf.Write(b)
	buf.Write(hdr.RecipientBlock)
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
