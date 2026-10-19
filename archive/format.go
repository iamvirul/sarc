// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import "github.com/iamvirul/sarc/crypto"

var Magic = [4]byte{'S', 'A', 'R', 'C'}

// Archive format versions. Version is what this build writes; extraction accepts
// every version listed here.
const (
	// Version1 derives every file key with its own PBKDF2 run.
	Version1 uint16 = 1
	// Version2 runs PBKDF2 once per archive and derives file keys with HKDF.
	Version2 uint16 = 2
	// Version is the format version written by ArchiveWriter.
	Version = Version2
)

const (
	// EntryTypeFile introduces a file entry.
	EntryTypeFile byte = 0x01
	// EntryTypeSolid introduces a solid group entry (Version2+): many small files packed
	// into one record stream that is compressed and sealed as a unit (see solid.go).
	EntryTypeSolid byte = 0x02
	// EntryTypeEnd follows the last file entry and precedes the footer (Version2+).
	// Version1 archives have no end marker; readers infer the end from the first footer byte.
	EntryTypeEnd byte = 0x00
	ReservedSize      = 32
	HMACSize          = crypto.HMACSize
)

// SizeBucket is a coarse file-size class stored in metadata instead of the exact byte count.
type SizeBucket uint8

const (
	BucketTiny   SizeBucket = iota // 0 - 1 KB
	BucketSmall                    // 1 KB - 10 KB
	BucketMedium                   // 10 KB - 100 KB
	BucketLarge                    // 100 KB - 1 MB
	BucketHuge                     // > 1 MB
)

// ArchiveHeader is the preamble written once at the start of the archive.
// Version1 layout: magic | version | archive_salt(32) | file_count_encrypted | reserved.
// Version2 layout: magic | version | recipient_block_len(4) | recipient_block |
// file_count_encrypted | reserved. FileCountEncrypted holds the file count sealed with
// the header key (see KeySchedule); opening it confirms the recovered CEK.
type ArchiveHeader struct {
	Magic              [4]byte
	Version            uint16
	ArchiveSalt        [crypto.SaltSize]byte // Version1 only
	RecipientBlock     []byte                // Version2+ (see recipients.go)
	FileCountEncrypted [FileCountSealedSize]byte
	Reserved           [ReservedSize]byte
}

// FileCountSealedSize is the length of the sealed file count: nonce | ciphertext | tag.
const FileCountSealedSize = 8 + crypto.NonceSize + crypto.GCMTagSize

// FrameHeader is a 32-byte random blob prepended to each file entry to break boundary patterns.
type FrameHeader [32]byte

// MetadataBlock holds per-file metadata sealed with the file-specific key.
// Nonce is plaintext; Ciphertext contains the sealed PlaintextMetadata.
type MetadataBlock struct {
	Nonce      [crypto.NonceSize]byte
	Ciphertext []byte
}

// PlaintextMetadata is the in-memory form of file metadata before sealing.
// Codec is absent from Version1 metadata and decodes as CodecNone there.
type PlaintextMetadata struct {
	EncryptedFilename []byte
	SizeBucket        SizeBucket
	TimestampHash     [32]byte
	Permissions       uint32
	Codec             Codec
}

// DataBlock is one variable-length encrypted chunk of file content.
type DataBlock struct {
	Nonce      [crypto.NonceSize]byte
	Ciphertext []byte
}

// FileTrailer closes a file entry. PlaintextHMACSealed holds the HMAC of the full
// plaintext, sealed so it can be verified after decryption without re-hashing ciphertext.
type FileTrailer struct {
	RandomPadding       []byte
	PlaintextHMACNonce  [crypto.NonceSize]byte
	PlaintextHMACSealed []byte
	EntryChecksum       [8]byte
}

// FileEntry is the complete in-memory representation of one archived file.
// On-disk layout: FrameHeader | MetadataBlock | InterBlockPadding | DataBlocks | FileTrailer.
type FileEntry struct {
	EntryType     byte
	EntrySalt     [crypto.SaltSize]byte
	FrameHdr      FrameHeader
	Metadata      MetadataBlock
	InterBlockPad []byte
	DataBlocks    []DataBlock
	Trailer       FileTrailer
}

// ArchiveFooter is written after all file entries.
// ArchiveHMAC covers the entire preceding byte stream.
type ArchiveFooter struct {
	ArchiveHMAC [crypto.HMACSize]byte
	Reserved    [ReservedSize]byte
}
