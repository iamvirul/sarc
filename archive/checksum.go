// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// headerPrefixLen covers magic, version, and the Version2 recipient block length.
const headerPrefixLen = 4 + 2 + 4

// ArchiveChecksum computes the footer checksum: SHA-256 over every archive byte before
// the footer, except that in an incremental archive the header's sealed session count,
// which each update rewrites in place, is hashed as zeros. That field is authenticated
// by the archive key instead. Other archives hash exactly as plain SHA-256.
type ArchiveChecksum struct {
	h    hash.Hash
	head []byte // leading bytes held until the header's layout is known
	done bool   // the header has been hashed; later bytes go straight to h
}

// NewArchiveChecksum returns a checksum for an archive written from its first byte.
func NewArchiveChecksum() *ArchiveChecksum {
	return &ArchiveChecksum{h: sha256.New()}
}

// ResumeArchiveChecksum restores a checksum from MarshalBinary output, taken after the
// header was written.
func ResumeArchiveChecksum(state []byte) (*ArchiveChecksum, error) {
	h := sha256.New()
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		return nil, fmt.Errorf("archive/checksum: restore state: %w", err)
	}
	return &ArchiveChecksum{h: h, done: true}, nil
}

// Write adds archive bytes in order. It never fails.
func (c *ArchiveChecksum) Write(p []byte) (int, error) {
	if c.done {
		return c.h.Write(p)
	}
	c.head = append(c.head, p...)
	c.flushHeader(false)
	return len(p), nil
}

// flushHeader hashes the held header bytes once their layout is known, masking the
// sealed count of an incremental header, or unconditionally when final is set.
func (c *ArchiveChecksum) flushHeader(final bool) {
	if len(c.head) < headerPrefixLen && !final {
		return
	}
	if len(c.head) >= headerPrefixLen && [4]byte(c.head[:4]) == Magic &&
		binary.LittleEndian.Uint16(c.head[4:]) == Version2 {
		blockLen := binary.LittleEndian.Uint32(c.head[6:])
		countOff := uint64(headerPrefixLen) + uint64(blockLen)
		flagOff := countOff + FileCountSealedSize
		if blockLen <= MaxRecipientBlockSize {
			if uint64(len(c.head)) <= flagOff && !final {
				return
			}
			if uint64(len(c.head)) > flagOff && c.head[flagOff]&HeaderFlagIncremental != 0 {
				clear(c.head[countOff:flagOff])
			}
		}
	}
	c.h.Write(c.head)
	c.head, c.done = nil, true
}

// Sum appends the checksum to b.
func (c *ArchiveChecksum) Sum(b []byte) []byte {
	if !c.done {
		c.flushHeader(true)
	}
	return c.h.Sum(b)
}

// MarshalBinary returns the checksum state, for a Checkpoint. It fails before the
// header has been hashed.
func (c *ArchiveChecksum) MarshalBinary() ([]byte, error) {
	if !c.done {
		return nil, errors.New("archive/checksum: header not yet hashed")
	}
	return c.h.(encoding.BinaryMarshaler).MarshalBinary()
}
