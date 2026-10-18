// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// A solid group entry uses the same framing as a file entry (salt, frame header, sealed
// metadata, padding, data blocks, trailer) but its plaintext is a record stream:
//
//	stream := record*
//	record := [2] name length | name | [4] permissions | [8] data length | data
//
// The stream is compressed as one unit per the entry's Codec, the result is split into
// data blocks, and the trailer HMAC and size cover the uncompressed stream.
const (
	// SolidMemberMaxSize is the largest file packed into a solid group; larger files are
	// stored as individual entries, where per-entry overhead is negligible.
	SolidMemberMaxSize = 1 << 20
	// MaxSolidStreamSize bounds a solid group's uncompressed record stream. Writers close
	// a group before exceeding it and readers refuse to decode past it.
	MaxSolidStreamSize = 8 << 20
	// solidRecordHeaderSize is the fixed part of a record (name, permissions, data lengths).
	solidRecordHeaderSize = 2 + 4 + 8
	maxSolidNameLen       = 0xFFFF
)

// ErrMalformedSolidStream is returned when a solid record stream cannot be parsed.
var ErrMalformedSolidStream = errors.New("archive: malformed solid stream")

// SolidMember is one file inside a solid group. Data returned by ParseSolidStream
// aliases the stream it was parsed from.
type SolidMember struct {
	Name        string
	Permissions uint32
	Data        []byte
}

// SolidRecordSize returns the encoded size of a record with the given name and data lengths.
func SolidRecordSize(nameLen, dataLen int) int {
	return solidRecordHeaderSize + nameLen + dataLen
}

// ValidSolidMemberName reports whether name can be stored in a solid group: a non-empty
// base name of at most 64 KiB with no path separator or NUL, and not "." or "..".
func ValidSolidMemberName(name string) bool {
	return name != "" && len(name) <= maxSolidNameLen && name != "." && name != ".." &&
		!strings.ContainsAny(name, "/\x00")
}

// AppendSolidRecord appends the encoded record for m to dst.
func AppendSolidRecord(dst []byte, m SolidMember) ([]byte, error) {
	if !ValidSolidMemberName(m.Name) {
		return dst, fmt.Errorf("archive/solid: invalid member name")
	}
	var hdr [8]byte
	binary.LittleEndian.PutUint16(hdr[:2], uint16(len(m.Name)))
	dst = append(dst, hdr[:2]...)
	dst = append(dst, m.Name...)
	binary.LittleEndian.PutUint32(hdr[:4], m.Permissions)
	dst = append(dst, hdr[:4]...)
	binary.LittleEndian.PutUint64(hdr[:8], uint64(len(m.Data)))
	dst = append(dst, hdr[:8]...)
	return append(dst, m.Data...), nil
}

// ParseSolidStream decodes every record in stream. It rejects truncated records,
// lengths running past the stream, invalid names, and an empty stream.
func ParseSolidStream(stream []byte) ([]SolidMember, error) {
	var members []SolidMember
	for off := 0; off < len(stream); {
		if len(stream)-off < 2 {
			return nil, fmt.Errorf("%w: truncated name length", ErrMalformedSolidStream)
		}
		nameLen := int(binary.LittleEndian.Uint16(stream[off:]))
		off += 2
		if len(stream)-off < nameLen+4+8 {
			return nil, fmt.Errorf("%w: truncated record header", ErrMalformedSolidStream)
		}
		name := string(stream[off : off+nameLen])
		off += nameLen
		if !ValidSolidMemberName(name) {
			return nil, fmt.Errorf("%w: invalid member name", ErrMalformedSolidStream)
		}
		perms := binary.LittleEndian.Uint32(stream[off:])
		off += 4
		dataLen := binary.LittleEndian.Uint64(stream[off:])
		off += 8
		if dataLen > uint64(len(stream)-off) {
			return nil, fmt.Errorf("%w: member data runs past stream", ErrMalformedSolidStream)
		}
		end := off + int(dataLen)
		members = append(members, SolidMember{Name: name, Permissions: perms, Data: stream[off:end:end]})
		off = end
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("%w: no members", ErrMalformedSolidStream)
	}
	return members, nil
}
