// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"

	"github.com/iamvirul/sarc/crypto"
)

// ArchiveWriter serialises a SARC archive to an io.Writer.
// A tee maintains a running SHA-256 over all bytes written for the footer HMAC.
type ArchiveWriter struct {
	w         io.Writer
	hasher    hash.Hash
	tee       io.Writer
	kd        *crypto.KeyDeriver
	masterKey [crypto.KeySize]byte
}

// NewArchiveWriter returns an ArchiveWriter that writes to w.
// archiveSalt must be generated before calling this and embedded in the header.
func NewArchiveWriter(w io.Writer, password string, archiveSalt [crypto.SaltSize]byte) (*ArchiveWriter, error) {
	kd := crypto.NewKeyDeriver(password)
	masterKey := kd.DeriveKey(archiveSalt)
	hasher := sha256.New()
	return &ArchiveWriter{
		w:         w,
		hasher:    hasher,
		tee:       io.MultiWriter(w, hasher),
		kd:        kd,
		masterKey: masterKey,
	}, nil
}

// WriteHeader serialises and writes the ArchiveHeader.
// fileCount is sealed with the master key before embedding.
func (aw *ArchiveWriter) WriteHeader(hdr ArchiveHeader, fileCount uint64) error {
	em, err := crypto.NewEncryptionManager(aw.masterKey)
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
	return aw.writeTrailer(entry.Trailer)
}

// WriteFooter computes the archive HMAC and flushes the ArchiveFooter.
// No further writes must occur after this call.
func (aw *ArchiveWriter) WriteFooter() error {
	var footer ArchiveFooter
	copy(footer.ArchiveHMAC[:], aw.hasher.Sum(nil))
	if _, err := aw.w.Write(footer.ArchiveHMAC[:]); err != nil {
		return fmt.Errorf("archive/writer: footer HMAC: %w", err)
	}
	reserved := make([]byte, ReservedSize)
	if _, err := aw.w.Write(reserved); err != nil {
		return fmt.Errorf("archive/writer: footer reserved: %w", err)
	}
	return nil
}

// DeriveFileKey derives the per-file AES-256 key from the master password and salt.
func (aw *ArchiveWriter) DeriveFileKey(salt [crypto.SaltSize]byte) [crypto.KeySize]byte {
	return aw.kd.DeriveKey(salt)
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
