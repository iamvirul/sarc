// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// An incremental archive (HeaderFlagIncremental) grows by sessions. Each session
// appends pack entries holding its new chunks and then one index entry; the archive
// ends with a checkpoint, the end marker, and the footer:
//
//	header | (pack* index)+ | checkpoint | end marker | footer
//
// Pack and index entries use the file-entry framing, so their contents are encrypted
// and padded like any file; chunk boundaries and IDs never appear outside them. A pack's
// plaintext is its chunks' stored bytes, back to back. An update overwrites the old
// checkpoint, end marker, and footer with the new session and a fresh tail.
const (
	// EntryTypePack introduces a pack entry: chunk data of one session.
	EntryTypePack byte = 0x03
	// EntryTypeIndex introduces a session index entry (see SessionIndex).
	EntryTypeIndex byte = 0x04
	// EntryTypeCheckpoint introduces the checkpoint before the end marker of an
	// incremental archive. It is not encrypted (see Checkpoint).
	EntryTypeCheckpoint byte = 0x05

	// HeaderFlagIncremental is set in Reserved[0] of an incremental archive's header.
	HeaderFlagIncremental byte = 0x01

	// MaxPackSize bounds a pack's plaintext; writers start a new pack before exceeding it.
	MaxPackSize = 64 << 20
	// MaxIndexSize bounds a session index's plaintext.
	MaxIndexSize = 256 << 20
	// MaxStoredChunkSize bounds a chunk's stored (possibly compressed) size.
	MaxStoredChunkSize = MaxCDCChunkSize + zstdMaxOverhead

	// FooterSize is the length of the archive footer.
	FooterSize = HMACSize + ReservedSize
	// CheckpointSize is the fixed length of a checkpoint, including its type byte.
	CheckpointSize = 1 + len(checkpointMagic) + 8 + 2 + checkpointStateSize
	// TailSize is the length of an incremental archive's tail: checkpoint, end marker,
	// and footer.
	TailSize = CheckpointSize + 1 + FooterSize

	checkpointMagic     = "SARCCKP1"
	checkpointStateSize = 128
	indexMagic          = "SARCIDX1"
)

// ErrMalformedIndex is returned when a session index cannot be parsed.
var ErrMalformedIndex = errors.New("archive: malformed session index")

// ErrMalformedCheckpoint is returned when a checkpoint cannot be parsed.
var ErrMalformedCheckpoint = errors.New("archive: malformed checkpoint")

// ChunkRecord locates one chunk added by a session.
type ChunkRecord struct {
	ID        [HMACSize]byte // HMAC-SHA256 of the chunk under the chunk ID key
	Pack      uint32         // index into SessionIndex.Packs
	Offset    uint64         // offset of the stored bytes in the pack plaintext
	StoredLen uint32
	RawLen    uint32
	Codec     Codec
}

// FileVersion is the state of one entry as of a session. Chunks lists global chunk
// numbers (in the order chunks were added across all sessions) in file order; only
// regular files have chunks.
type FileVersion struct {
	Name       string
	Attributes Attributes
	Size       uint64
	Chunks     []uint64
}

// SessionIndex is the plaintext of an index entry: what one session added and changed.
// Chunks are numbered globally from FirstChunk; Files are new or changed files and
// Deleted the names removed since the previous session.
type SessionIndex struct {
	Session    uint64
	Time       int64  // Unix seconds
	PrevIndex  uint64 // archive offset of the previous session's index entry; 0 for the first
	FirstChunk uint64
	Packs      []uint64 // archive offsets of this session's pack entries
	Chunks     []ChunkRecord
	Files      []FileVersion
	Deleted    []string
}

// Marshal encodes si. Integers are unsigned varints except the timestamps.
func (si *SessionIndex) Marshal() ([]byte, error) {
	b := append([]byte(nil), indexMagic...)
	b = binary.AppendUvarint(b, si.Session)
	b = binary.AppendVarint(b, si.Time)
	b = binary.AppendUvarint(b, si.PrevIndex)
	b = binary.AppendUvarint(b, si.FirstChunk)
	b = binary.AppendUvarint(b, uint64(len(si.Packs)))
	for _, off := range si.Packs {
		b = binary.AppendUvarint(b, off)
	}
	b = binary.AppendUvarint(b, uint64(len(si.Chunks)))
	for _, c := range si.Chunks {
		b = append(b, c.ID[:]...)
		b = binary.AppendUvarint(b, uint64(c.Pack))
		b = binary.AppendUvarint(b, c.Offset)
		b = binary.AppendUvarint(b, uint64(c.StoredLen))
		b = binary.AppendUvarint(b, uint64(c.RawLen))
		b = append(b, byte(c.Codec))
	}
	b = binary.AppendUvarint(b, uint64(len(si.Files)))
	for _, f := range si.Files {
		if !ValidEntryName(f.Name) {
			return nil, fmt.Errorf("archive/incremental: invalid file name")
		}
		if f.Attributes.Kind != KindRegular && (f.Size != 0 || len(f.Chunks) != 0) {
			return nil, fmt.Errorf("archive/incremental: %s entry with data", f.Attributes.Kind)
		}
		b = appendString(b, f.Name)
		attrs, err := AppendAttributes(nil, f.Attributes)
		if err != nil {
			return nil, err
		}
		b = binary.AppendUvarint(b, uint64(len(attrs)))
		b = append(b, attrs...)
		b = binary.AppendUvarint(b, f.Size)
		b = binary.AppendUvarint(b, uint64(len(f.Chunks)))
		// Chunk numbers are delta-encoded: consecutive new chunks cost one byte each.
		var prev uint64
		for _, n := range f.Chunks {
			b = binary.AppendVarint(b, int64(n-prev))
			prev = n
		}
	}
	b = binary.AppendUvarint(b, uint64(len(si.Deleted)))
	for _, name := range si.Deleted {
		if !ValidEntryName(name) {
			return nil, fmt.Errorf("archive/incremental: invalid deleted name")
		}
		b = appendString(b, name)
	}
	if len(b) > MaxIndexSize {
		return nil, fmt.Errorf("archive/incremental: index is %d bytes, maximum %d", len(b), MaxIndexSize)
	}
	return b, nil
}

func appendString(b []byte, s string) []byte {
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

// ParseSessionIndex decodes and validates an index: names must be safe, chunks must lie
// in a listed pack within MaxPackSize with sizes in bounds and a known codec, and files
// may only reference chunks numbered below FirstChunk+len(Chunks).
func ParseSessionIndex(b []byte) (*SessionIndex, error) {
	if len(b) > MaxIndexSize || !bytes.HasPrefix(b, []byte(indexMagic)) {
		return nil, fmt.Errorf("%w: bad magic or size", ErrMalformedIndex)
	}
	d := indexDecoder{b: b[len(indexMagic):]}
	si := &SessionIndex{
		Session:    d.uvarint(),
		Time:       d.varint(),
		PrevIndex:  d.uvarint(),
		FirstChunk: d.uvarint(),
	}
	si.Packs = make([]uint64, d.count(1))
	for i := range si.Packs {
		si.Packs[i] = d.uvarint()
	}
	si.Chunks = make([]ChunkRecord, d.count(HMACSize+5))
	for i := range si.Chunks {
		si.Chunks[i] = d.chunk(len(si.Packs))
	}
	chunkLimit := si.FirstChunk + uint64(len(si.Chunks))
	si.Files = make([]FileVersion, d.count(5))
	for i := range si.Files {
		si.Files[i] = d.file(chunkLimit)
	}
	si.Deleted = make([]string, d.count(2))
	for i := range si.Deleted {
		si.Deleted[i] = d.name()
	}
	if d.err != nil {
		return nil, d.err
	}
	if len(d.b) != 0 {
		return nil, fmt.Errorf("%w: trailing bytes", ErrMalformedIndex)
	}
	if si.Session == 0 {
		return nil, fmt.Errorf("%w: session 0", ErrMalformedIndex)
	}
	return si, nil
}

// indexDecoder reads index or directory fields, recording the first error and
// returning zero values after it. Errors wrap malformed, or ErrMalformedIndex when it
// is nil.
type indexDecoder struct {
	b         []byte
	err       error
	malformed error
}

func (d *indexDecoder) fail(what string) {
	if d.err == nil {
		kind := d.malformed
		if kind == nil {
			kind = ErrMalformedIndex
		}
		d.err = fmt.Errorf("%w: %s", kind, what)
	}
	d.b = nil
}

func (d *indexDecoder) uvarint() uint64 {
	v, n := binary.Uvarint(d.b)
	if n <= 0 {
		d.fail("bad varint")
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *indexDecoder) varint() int64 {
	v, n := binary.Varint(d.b)
	if n <= 0 {
		d.fail("bad varint")
		return 0
	}
	d.b = d.b[n:]
	return v
}

// count reads an element count and rejects one that the remaining bytes cannot hold at
// minSize bytes per element, so a hostile count cannot force a large allocation.
func (d *indexDecoder) count(minSize int) int {
	n := d.uvarint()
	if n > uint64(len(d.b)/minSize) {
		d.fail("count exceeds remaining data")
		return 0
	}
	return int(n)
}

func (d *indexDecoder) bytes(n int) []byte {
	if n > len(d.b) {
		d.fail("truncated")
		return nil
	}
	out := d.b[:n]
	d.b = d.b[n:]
	return out
}

func (d *indexDecoder) readByte() byte {
	b := d.bytes(1)
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

func (d *indexDecoder) name() string {
	n := d.uvarint()
	if n > MaxEntryNameLen {
		d.fail("name too long")
		return ""
	}
	name := string(d.bytes(int(n)))
	if d.err == nil && !ValidEntryName(name) {
		d.fail("invalid name")
	}
	return name
}

func (d *indexDecoder) chunk(packs int) ChunkRecord {
	var c ChunkRecord
	copy(c.ID[:], d.bytes(HMACSize))
	pack, offset, stored, raw := d.uvarint(), d.uvarint(), d.uvarint(), d.uvarint()
	codec := Codec(d.readByte())
	switch {
	case d.err != nil:
	case pack >= uint64(packs):
		d.fail("chunk in unknown pack")
	case stored == 0 || stored > MaxStoredChunkSize || raw == 0 || raw > MaxCDCChunkSize:
		d.fail("chunk size out of range")
	case offset > MaxPackSize || stored > MaxPackSize-offset:
		d.fail("chunk past pack end")
	case codec != CodecNone && codec != CodecZstd:
		d.fail("unknown chunk codec")
	case codec == CodecNone && stored != raw:
		d.fail("stored size of uncompressed chunk differs")
	}
	c.Pack, c.Offset, c.StoredLen, c.RawLen, c.Codec = uint32(pack), offset, uint32(stored), uint32(raw), codec
	return c
}

func (d *indexDecoder) file(chunkLimit uint64) FileVersion {
	f := FileVersion{Name: d.name()}
	attrsLen := d.uvarint()
	if attrsLen > MaxAttributesSize {
		d.fail("attributes too large")
	}
	if raw := d.bytes(int(attrsLen)); d.err == nil {
		attrs, err := ParseAttributes(raw)
		if err != nil {
			d.fail("bad attributes")
		}
		f.Attributes = attrs
	}
	f.Size = d.uvarint()
	f.Chunks = make([]uint64, d.count(1))
	var prev uint64
	for i := range f.Chunks {
		n := prev + uint64(d.varint())
		if d.err == nil && n >= chunkLimit {
			d.fail("file references an unknown chunk")
		}
		f.Chunks[i], prev = n, n
	}
	if d.err == nil && f.Attributes.Kind != KindRegular && (f.Size != 0 || len(f.Chunks) != 0) {
		d.fail("directory or link with data")
	}
	return f
}

// Checkpoint sits before the end marker of an incremental archive. LastIndex locates
// the newest session index; HashState is the marshaled SHA-256 state of every archive
// byte before the checkpoint, so an update can extend the footer checksum without
// rereading the archive. Neither is trusted for security: the index it points to is
// authenticated, and the footer is only a corruption check.
type Checkpoint struct {
	LastIndex uint64
	HashState []byte
}

// Marshal encodes c as CheckpointSize bytes, starting with its entry type.
func (c Checkpoint) Marshal() ([]byte, error) {
	if len(c.HashState) > checkpointStateSize {
		return nil, fmt.Errorf("archive/incremental: hash state is %d bytes, maximum %d", len(c.HashState), checkpointStateSize)
	}
	b := make([]byte, 0, CheckpointSize)
	b = append(b, EntryTypeCheckpoint)
	b = append(b, checkpointMagic...)
	b = binary.LittleEndian.AppendUint64(b, c.LastIndex)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(c.HashState)))
	b = append(b, c.HashState...)
	return append(b, make([]byte, CheckpointSize-len(b))...), nil
}

// ParseCheckpoint decodes a CheckpointSize-byte checkpoint.
func ParseCheckpoint(b []byte) (Checkpoint, error) {
	if len(b) != CheckpointSize || b[0] != EntryTypeCheckpoint || string(b[1:1+len(checkpointMagic)]) != checkpointMagic {
		return Checkpoint{}, fmt.Errorf("%w: bad type or magic", ErrMalformedCheckpoint)
	}
	off := 1 + len(checkpointMagic)
	c := Checkpoint{LastIndex: binary.LittleEndian.Uint64(b[off:])}
	off += 8
	n := int(binary.LittleEndian.Uint16(b[off:]))
	off += 2
	if n > checkpointStateSize {
		return Checkpoint{}, fmt.Errorf("%w: hash state too long", ErrMalformedCheckpoint)
	}
	c.HashState = bytes.Clone(b[off : off+n])
	return c, nil
}
