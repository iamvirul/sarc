// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// FileKind is the type of filesystem object an entry restores.
type FileKind uint8

// File kinds. Directories, symlinks, and hard links carry no data.
const (
	KindRegular FileKind = iota
	KindDirectory
	KindSymlink
	KindHardlink
)

func (k FileKind) String() string {
	switch k {
	case KindRegular:
		return "regular"
	case KindDirectory:
		return "directory"
	case KindSymlink:
		return "symlink"
	case KindHardlink:
		return "hardlink"
	}
	return fmt.Sprintf("kind(%d)", uint8(k))
}

// Limits on attributes, so a hostile archive cannot force large allocations.
const (
	// ModeMask covers the permission, setuid, setgid, and sticky bits.
	ModeMask = 0o7777
	// MaxLinkTargetLen bounds a symlink or hard link target.
	MaxLinkTargetLen = 4096
	// MaxXattrs bounds the extended attributes of one file.
	MaxXattrs = 1024
	// MaxXattrNameLen bounds an extended attribute name.
	MaxXattrNameLen = 255
	// MaxXattrsSize bounds the encoded extended attributes of one file. Larger sets
	// (such as a big macOS resource fork) are not stored.
	MaxXattrsSize = 1 << 20
	// MaxAttributesSize bounds encoded attributes.
	MaxAttributesSize = MaxXattrsSize + MaxLinkTargetLen + 64
)

// ErrMalformedAttributes is returned when encoded attributes cannot be parsed.
var ErrMalformedAttributes = errors.New("archive: malformed attributes")

// Owner is a numeric user and group ID, stored only when ownership is preserved.
type Owner struct {
	UID uint32
	GID uint32
}

// Xattr is one extended attribute. On Linux, POSIX ACLs are the system.posix_acl_*
// attributes; on macOS, a resource fork is com.apple.ResourceFork.
type Xattr struct {
	Name  string
	Value []byte
}

// Attributes are the filesystem metadata of an entry beyond its name and data.
type Attributes struct {
	Kind FileKind
	// Mode holds the permission bits plus setuid (0o4000), setgid (0o2000), and sticky
	// (0o1000), as in chmod.
	Mode uint32
	// ModTime is the modification time in Unix nanoseconds; 0 when unknown.
	ModTime int64
	// LinkTarget is a symlink's target, or for a hard link the stored name of the entry
	// it links to.
	LinkTarget string
	Owner      *Owner
	Xattrs     []Xattr
}

const attributesHasOwner = 0x01

// AppendAttributes appends the encoding of a to dst:
//
//	kind(1) | mode(4) | mtime(8) | flags(1) | [uid(4) gid(4)] | target_len(2) | target |
//	xattr_count(2) | (name_len(1) | name | value_len(4) | value)*
func AppendAttributes(dst []byte, a Attributes) ([]byte, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	dst = append(dst, byte(a.Kind))
	dst = binary.LittleEndian.AppendUint32(dst, a.Mode)
	dst = binary.LittleEndian.AppendUint64(dst, uint64(a.ModTime))
	var flags byte
	if a.Owner != nil {
		flags |= attributesHasOwner
	}
	dst = append(dst, flags)
	if a.Owner != nil {
		dst = binary.LittleEndian.AppendUint32(dst, a.Owner.UID)
		dst = binary.LittleEndian.AppendUint32(dst, a.Owner.GID)
	}
	dst = binary.LittleEndian.AppendUint16(dst, uint16(len(a.LinkTarget)))
	dst = append(dst, a.LinkTarget...)
	dst = binary.LittleEndian.AppendUint16(dst, uint16(len(a.Xattrs)))
	for _, x := range a.Xattrs {
		dst = append(dst, byte(len(x.Name)))
		dst = append(dst, x.Name...)
		dst = binary.LittleEndian.AppendUint32(dst, uint32(len(x.Value)))
		dst = append(dst, x.Value...)
	}
	return dst, nil
}

// XattrsSize returns the encoded size of xattrs.
func XattrsSize(xattrs []Xattr) int {
	n := 0
	for _, x := range xattrs {
		n += 1 + len(x.Name) + 4 + len(x.Value)
	}
	return n
}

func (a Attributes) validate() error {
	switch {
	case a.Kind > KindHardlink:
		return fmt.Errorf("%w: unknown kind %d", ErrMalformedAttributes, a.Kind)
	case a.Mode&^ModeMask != 0:
		return fmt.Errorf("%w: mode has bits outside %o", ErrMalformedAttributes, ModeMask)
	case len(a.LinkTarget) > MaxLinkTargetLen:
		return fmt.Errorf("%w: link target too long", ErrMalformedAttributes)
	case (a.Kind == KindSymlink || a.Kind == KindHardlink) != (a.LinkTarget != ""):
		return fmt.Errorf("%w: only links have a non-empty target", ErrMalformedAttributes)
	case a.Kind == KindHardlink && !ValidEntryName(a.LinkTarget):
		return fmt.Errorf("%w: hard link target is not a safe name", ErrMalformedAttributes)
	case len(a.Xattrs) > MaxXattrs || XattrsSize(a.Xattrs) > MaxXattrsSize:
		return fmt.Errorf("%w: extended attributes too large", ErrMalformedAttributes)
	}
	for _, x := range a.Xattrs {
		if x.Name == "" || len(x.Name) > MaxXattrNameLen {
			return fmt.Errorf("%w: bad extended attribute name", ErrMalformedAttributes)
		}
	}
	return nil
}

// ParseAttributes decodes attributes encoded by AppendAttributes and validates them.
// Byte slices in the result alias b.
func ParseAttributes(b []byte) (Attributes, error) {
	d := attrDecoder{b: b}
	var a Attributes
	a.Kind = FileKind(d.byte())
	a.Mode = d.u32()
	a.ModTime = int64(d.u64())
	flags := d.byte()
	if flags&^attributesHasOwner != 0 {
		return Attributes{}, fmt.Errorf("%w: unknown flags", ErrMalformedAttributes)
	}
	if flags&attributesHasOwner != 0 {
		a.Owner = &Owner{UID: d.u32(), GID: d.u32()}
	}
	a.LinkTarget = string(d.bytes(int(d.u16())))
	count := int(d.u16())
	if count > MaxXattrs {
		return Attributes{}, fmt.Errorf("%w: too many extended attributes", ErrMalformedAttributes)
	}
	for i := 0; i < count && d.err == nil; i++ {
		name := string(d.bytes(int(d.byte())))
		size := d.u32()
		if size > MaxXattrsSize {
			return Attributes{}, fmt.Errorf("%w: extended attribute too large", ErrMalformedAttributes)
		}
		a.Xattrs = append(a.Xattrs, Xattr{Name: name, Value: d.bytes(int(size))})
	}
	if d.err != nil {
		return Attributes{}, d.err
	}
	if len(d.b) != 0 {
		return Attributes{}, fmt.Errorf("%w: trailing bytes", ErrMalformedAttributes)
	}
	if err := a.validate(); err != nil {
		return Attributes{}, err
	}
	return a, nil
}

// attrDecoder reads fixed-size fields, recording the first truncation.
type attrDecoder struct {
	b   []byte
	err error
}

func (d *attrDecoder) bytes(n int) []byte {
	if d.err != nil || n > len(d.b) {
		if d.err == nil {
			d.err = fmt.Errorf("%w: truncated", ErrMalformedAttributes)
		}
		return nil
	}
	out := d.b[:n:n]
	d.b = d.b[n:]
	return out
}

func (d *attrDecoder) byte() byte {
	if b := d.bytes(1); b != nil {
		return b[0]
	}
	return 0
}

func (d *attrDecoder) u16() uint16 {
	if b := d.bytes(2); b != nil {
		return binary.LittleEndian.Uint16(b)
	}
	return 0
}

func (d *attrDecoder) u32() uint32 {
	if b := d.bytes(4); b != nil {
		return binary.LittleEndian.Uint32(b)
	}
	return 0
}

func (d *attrDecoder) u64() uint64 {
	if b := d.bytes(8); b != nil {
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}
