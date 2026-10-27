// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// A Version2 archive written in one pass ends its entries with a directory listing
// every entry, then a locator pointing at it:
//
//	header | entries | directory | locator | end marker | footer
//
// The directory uses the file-entry framing, so it is encrypted and padded like any
// file. The locator is not encrypted and sits at a fixed distance from the end of the
// archive proper, so a reader with random access lists an archive by reading its
// header, the locator, and the directory, without touching any data block. Sequential
// readers skip both. Incremental archives have no directory: their session indexes
// serve the same purpose.
const (
	// EntryTypeDirectory introduces the directory entry (see DirectoryRecord).
	EntryTypeDirectory byte = 0x06
	// EntryTypeDirectoryLocator introduces the locator after the directory entry.
	EntryTypeDirectoryLocator byte = 0x07

	// MaxDirectorySize bounds a directory's plaintext. A writer whose directory would
	// exceed it writes none, and readers list the archive by scanning its entries.
	MaxDirectorySize = 16 << 20
	// DirectoryLocatorSize is the fixed length of a locator, including its type byte.
	DirectoryLocatorSize = 1 + len(directoryLocatorMagic) + 8
	// DirectoryTailSize is the length of the end of an archive proper that holds a
	// directory: locator, end marker, and footer.
	DirectoryTailSize = DirectoryLocatorSize + 1 + FooterSize

	directoryMagic        = "SARCDIR1"
	directoryLocatorMagic = "SARCDLC1"
	directoryFlagSolid    = 0x01
)

// ErrMalformedDirectory is returned when a directory or its locator cannot be parsed.
var ErrMalformedDirectory = errors.New("archive: malformed directory")

// DirectoryRecord describes one listed file. Offset is the archive offset of the type
// byte of the entry holding it; members of one solid group share it. StoredSize is the
// encoded payload size, a member's proportional share of its group's payload.
type DirectoryRecord struct {
	Offset       uint64
	Name         string
	Attributes   Attributes
	SizeBucket   SizeBucket
	Codec        Codec
	Solid        bool
	OriginalSize uint64
	StoredSize   uint64
}

// NewDirectory returns the start of a directory's plaintext; append records to it with
// AppendDirectoryRecord.
func NewDirectory() []byte {
	return append([]byte(nil), directoryMagic...)
}

// AppendDirectoryRecord appends the encoding of r to dir.
func AppendDirectoryRecord(dir []byte, r DirectoryRecord) ([]byte, error) {
	if !ValidEntryName(r.Name) {
		return nil, fmt.Errorf("archive/directory: invalid entry name")
	}
	if r.Attributes.Kind != KindRegular && (r.OriginalSize != 0 || r.StoredSize != 0) {
		return nil, fmt.Errorf("archive/directory: %s entry with data", r.Attributes.Kind)
	}
	attrs, err := AppendAttributes(nil, r.Attributes)
	if err != nil {
		return nil, err
	}
	var flags byte
	if r.Solid {
		flags |= directoryFlagSolid
	}
	dir = binary.AppendUvarint(dir, r.Offset)
	dir = appendString(dir, r.Name)
	dir = append(dir, flags, byte(r.SizeBucket), byte(r.Codec))
	dir = binary.AppendUvarint(dir, uint64(len(attrs)))
	dir = append(dir, attrs...)
	dir = binary.AppendUvarint(dir, r.OriginalSize)
	return binary.AppendUvarint(dir, r.StoredSize), nil
}

// ParseDirectory decodes and validates a directory's plaintext: names must be safe,
// buckets and codecs known, and only regular files may have sizes.
func ParseDirectory(b []byte) ([]DirectoryRecord, error) {
	if len(b) > MaxDirectorySize || !bytes.HasPrefix(b, []byte(directoryMagic)) {
		return nil, fmt.Errorf("%w: bad magic or size", ErrMalformedDirectory)
	}
	d := indexDecoder{b: b[len(directoryMagic):], malformed: ErrMalformedDirectory}
	var records []DirectoryRecord
	for len(d.b) > 0 && d.err == nil {
		records = append(records, d.directoryRecord())
	}
	if d.err != nil {
		return nil, d.err
	}
	return records, nil
}

func (d *indexDecoder) directoryRecord() DirectoryRecord {
	r := DirectoryRecord{Offset: d.uvarint(), Name: d.name()}
	flags, bucket, codec := d.readByte(), SizeBucket(d.readByte()), Codec(d.readByte())
	r.Solid, r.SizeBucket, r.Codec = flags&directoryFlagSolid != 0, bucket, codec
	attrsLen := d.uvarint()
	if attrsLen > MaxAttributesSize {
		d.fail("attributes too large")
	}
	if raw := d.bytes(int(attrsLen)); d.err == nil {
		attrs, err := ParseAttributes(raw)
		if err != nil {
			d.fail("bad attributes")
		}
		r.Attributes = attrs
	}
	r.OriginalSize, r.StoredSize = d.uvarint(), d.uvarint()
	switch {
	case d.err != nil:
	case flags&^directoryFlagSolid != 0:
		d.fail("unknown flags")
	case bucket > BucketHuge:
		d.fail("unknown size bucket")
	case codec != CodecNone && codec != CodecZstd:
		d.fail("unknown codec")
	case r.Attributes.Kind != KindRegular && (r.OriginalSize != 0 || r.StoredSize != 0):
		d.fail("directory or link with data")
	}
	return r
}

// AppendDirectoryLocator appends the locator of the directory entry at offset to dst.
func AppendDirectoryLocator(dst []byte, offset uint64) []byte {
	dst = append(dst, EntryTypeDirectoryLocator)
	dst = append(dst, directoryLocatorMagic...)
	return binary.LittleEndian.AppendUint64(dst, offset)
}

// ParseDirectoryLocator decodes a DirectoryLocatorSize-byte locator and returns the
// offset of the directory entry.
func ParseDirectoryLocator(b []byte) (uint64, error) {
	if len(b) != DirectoryLocatorSize || b[0] != EntryTypeDirectoryLocator ||
		string(b[1:1+len(directoryLocatorMagic)]) != directoryLocatorMagic {
		return 0, fmt.Errorf("%w: bad locator", ErrMalformedDirectory)
	}
	return binary.LittleEndian.Uint64(b[1+len(directoryLocatorMagic):]), nil
}
