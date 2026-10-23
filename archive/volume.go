// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// A split archive is the byte stream of a normal archive cut into volumes, each a file
// of at most the chosen volume size:
//
//	volume  := header | payload | checksum(32)
//	header  := "SARCVOL1" | archive_id(16) | index(4) | flags(1) | reserved(3) | payload_len(8)
//
// Concatenating the payloads in index order gives back the archive exactly, so every
// reader works unchanged once the volumes are joined. archive_id is random and shared by
// all volumes of one archive; index counts from 1; the last volume sets
// VolumeFlagLast. checksum is SHA-256(payload || header), so each volume can be checked
// on its own and a damaged, missing, reordered, or foreign volume is identified by
// number. Like the footer, it detects corruption; authenticity comes from the archive
// inside.
const (
	// VolumeHeaderSize is the length of a volume header.
	VolumeHeaderSize = len(volumeMagic) + VolumeIDSize + 4 + 1 + 3 + 8
	// VolumeChecksumSize is the length of the checksum ending each volume.
	VolumeChecksumSize = 32
	// VolumeOverhead is the framing added to each volume.
	VolumeOverhead = VolumeHeaderSize + VolumeChecksumSize
	// VolumeIDSize is the length of the random archive ID.
	VolumeIDSize = 16
	// VolumeFlagLast marks the final volume.
	VolumeFlagLast byte = 0x01

	volumeMagic = "SARCVOL1"
)

// ErrMalformedVolumeHeader is returned when a volume header cannot be parsed.
var ErrMalformedVolumeHeader = errors.New("archive: malformed volume header")

// VolumeHeader is the decoded header of one volume.
type VolumeHeader struct {
	ArchiveID  [VolumeIDSize]byte
	Index      uint32
	Last       bool
	PayloadLen uint64
}

// Marshal encodes h as VolumeHeaderSize bytes.
func (h VolumeHeader) Marshal() []byte {
	b := make([]byte, 0, VolumeHeaderSize)
	b = append(b, volumeMagic...)
	b = append(b, h.ArchiveID[:]...)
	b = binary.LittleEndian.AppendUint32(b, h.Index)
	var flags byte
	if h.Last {
		flags |= VolumeFlagLast
	}
	b = append(b, flags, 0, 0, 0)
	return binary.LittleEndian.AppendUint64(b, h.PayloadLen)
}

// IsVolumeHeader reports whether b starts with the volume magic.
func IsVolumeHeader(b []byte) bool {
	return len(b) >= len(volumeMagic) && string(b[:len(volumeMagic)]) == volumeMagic
}

// ParseVolumeHeader decodes a VolumeHeaderSize-byte header. Unknown flags, nonzero
// reserved bytes, and index 0 are rejected.
func ParseVolumeHeader(b []byte) (VolumeHeader, error) {
	if len(b) != VolumeHeaderSize || !IsVolumeHeader(b) {
		return VolumeHeader{}, fmt.Errorf("%w: bad magic or size", ErrMalformedVolumeHeader)
	}
	var h VolumeHeader
	off := len(volumeMagic)
	off += copy(h.ArchiveID[:], b[off:])
	h.Index = binary.LittleEndian.Uint32(b[off:])
	off += 4
	flags := b[off]
	if flags&^VolumeFlagLast != 0 || b[off+1] != 0 || b[off+2] != 0 || b[off+3] != 0 {
		return VolumeHeader{}, fmt.Errorf("%w: unknown flags", ErrMalformedVolumeHeader)
	}
	h.Last = flags&VolumeFlagLast != 0
	off += 4
	h.PayloadLen = binary.LittleEndian.Uint64(b[off:])
	if h.Index == 0 {
		return VolumeHeader{}, fmt.Errorf("%w: index 0", ErrMalformedVolumeHeader)
	}
	return h, nil
}
