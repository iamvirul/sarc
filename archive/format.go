// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import "github.com/iamvirul/sarc/crypto"

var Magic = [4]byte{'S', 'A', 'R', 'C'}

const (
	Version       uint16 = 1
	EntryTypeFile byte   = 0x01
	ReservedSize         = 32
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

// ArchiveHeader is the fixed preamble written once at the start of the archive.
// FileCountEncrypted holds file count sealed with the master key.
type ArchiveHeader struct {
	Magic              [4]byte
	Version            uint16
	ArchiveSalt        [crypto.SaltSize]byte
	FileCountEncrypted [8 + crypto.NonceSize + crypto.GCMTagSize]byte
	Reserved           [ReservedSize]byte
}

// FrameHeader is a 32-byte random blob prepended to each file entry to break boundary patterns.
type FrameHeader [32]byte

// MetadataBlock holds per-file metadata sealed with the file-specific key.
// Nonce is plaintext; Ciphertext contains the sealed PlaintextMetadata.
type MetadataBlock struct {
	Nonce      [crypto.NonceSize]byte
	Ciphertext []byte
}

// PlaintextMetadata is the in-memory form of file metadata before sealing.
type PlaintextMetadata struct {
	EncryptedFilename []byte
	SizeBucket        SizeBucket
	TimestampHash     [32]byte
	Permissions       uint32
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
