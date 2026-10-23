// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"regexp"

	"github.com/iamvirul/sarc/archive"
)

// MinVolumeSize is the smallest volume size a split archive may use.
const MinVolumeSize = 64 << 10

// volumeName matches a volume file name: the base name, a dot, and three or more digits.
var volumeName = regexp.MustCompile(`^(.+)\.(\d{3,})$`)

// VolumeError identifies a missing, damaged, reordered, or foreign volume of a split
// archive.
type VolumeError struct {
	Index   int    // 1-based volume number
	Path    string // the volume's file, empty when volumes are read from one stream
	Problem string
}

func (e *VolumeError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("volume %d (%s): %s", e.Index, e.Path, e.Problem)
	}
	return fmt.Sprintf("volume %d: %s", e.Index, e.Problem)
}

// VolumePath returns the file name of volume index (from 1) of the split archive base:
// base.001, base.002, and so on.
func VolumePath(base string, index int) string {
	return fmt.Sprintf("%s.%03d", base, index)
}

// VolumeWriter splits an archive into volumes (see archive.VolumeHeader). It is an
// io.Writer for the archivers; Close must be called to finish the last volume.
type VolumeWriter struct {
	base     string
	capacity int64 // payload bytes per volume
	id       [archive.VolumeIDSize]byte
	index    int
	f        *os.File
	written  int64
	sum      hash.Hash
	paths    []string
	err      error
	closed   bool
}

// CreateVolumes returns a VolumeWriter for volumes of at most volumeSize bytes named
// base.001, base.002, and so on. Volumes are created as data arrives, replacing files
// of the same names.
func CreateVolumes(base string, volumeSize int64) (*VolumeWriter, error) {
	if volumeSize < MinVolumeSize {
		return nil, fatal(ErrCodeInvalidOption, fmt.Sprintf("volume size must be at least %d bytes", MinVolumeSize), nil)
	}
	v := &VolumeWriter{base: base, capacity: volumeSize - int64(archive.VolumeOverhead)}
	if _, err := rand.Read(v.id[:]); err != nil {
		return nil, fatal(ErrCodeWriteFailed, "generate archive id", err)
	}
	return v, nil
}

// Paths returns the volume files written so far.
func (v *VolumeWriter) Paths() []string { return v.paths }

// Write appends archive bytes, starting a new volume whenever the current one is full.
func (v *VolumeWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		if v.err != nil {
			return total, v.err
		}
		if v.f == nil || v.written == v.capacity {
			if v.f != nil {
				v.err = v.finishVolume(false)
				continue
			}
			v.err = v.openVolume()
			continue
		}
		n := int(min(int64(len(p)), v.capacity-v.written))
		if _, err := v.f.Write(p[:n]); err != nil {
			v.err = fatal(ErrCodeWriteFailed, "write volume", err)
			return total, v.err
		}
		v.sum.Write(p[:n])
		v.written += int64(n)
		total += n
		p = p[n:]
	}
	return total, nil
}

// Close finishes the last volume and removes stale volumes numbered after it that an
// earlier, larger archive of the same name left behind. It is safe to call twice.
func (v *VolumeWriter) Close() error {
	if v.closed {
		return v.err
	}
	v.closed = true
	if v.err != nil {
		if v.f != nil {
			v.f.Close()
		}
		return v.err
	}
	if v.f == nil {
		if v.err = v.openVolume(); v.err != nil {
			return v.err
		}
	}
	if v.err = v.finishVolume(true); v.err != nil {
		return v.err
	}
	v.err = removeStaleVolumes(v.base, v.index+1)
	return v.err
}

func (v *VolumeWriter) openVolume() error {
	v.index++
	path := VolumePath(v.base, v.index)
	f, err := os.Create(path)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "create volume", err)
	}
	// The header is rewritten with the real payload length and flags when the volume ends.
	header := archive.VolumeHeader{ArchiveID: v.id, Index: uint32(v.index), PayloadLen: uint64(v.capacity)}.Marshal()
	if _, err := f.Write(header); err != nil {
		f.Close()
		return fatal(ErrCodeWriteFailed, "write volume header", err)
	}
	v.f, v.written, v.sum = f, 0, sha256.New()
	v.paths = append(v.paths, path)
	return nil
}

func (v *VolumeWriter) finishVolume(last bool) error {
	f := v.f
	v.f = nil
	header := archive.VolumeHeader{ArchiveID: v.id, Index: uint32(v.index), Last: last, PayloadLen: uint64(v.written)}.Marshal()
	if _, err := f.WriteAt(header, 0); err != nil {
		f.Close()
		return fatal(ErrCodeWriteFailed, "write volume header", err)
	}
	v.sum.Write(header)
	if _, err := f.Write(v.sum.Sum(nil)); err != nil {
		f.Close()
		return fatal(ErrCodeWriteFailed, "write volume checksum", err)
	}
	if err := f.Close(); err != nil {
		return fatal(ErrCodeWriteFailed, "close volume", err)
	}
	return nil
}

// removeStaleVolumes deletes base.from, base.from+1, ... while they exist and start with
// a volume header, so a shorter archive never leaves volumes of an older one beside it.
func removeStaleVolumes(base string, from int) error {
	for i := from; ; i++ {
		path := VolumePath(base, i)
		if !startsWithVolumeHeader(path) {
			return nil
		}
		if err := os.Remove(path); err != nil {
			return fatal(ErrCodeWriteFailed, "remove stale volume", err)
		}
	}
}

func startsWithVolumeHeader(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, archive.VolumeHeaderSize)
	_, err = io.ReadFull(f, head)
	return err == nil && archive.IsVolumeHeader(head)
}

// FindVolumes resolves path to the base name of a split archive: path may be any of its
// volumes (base.NNN starting with a volume header) or the base name itself when
// base.001 exists. It reports false for anything else, which is read as a single file.
func FindVolumes(path string) (string, bool) {
	if m := volumeName.FindStringSubmatch(path); m != nil && startsWithVolumeHeader(path) {
		return m[1], true
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) && startsWithVolumeHeader(VolumePath(path, 1)) {
		return path, true
	}
	return "", false
}

// volumeSource opens volume index (from 1) and returns it with its file name, or "" for
// a stream.
type volumeSource func(index int) (io.Reader, string, error)

// VolumeReader joins the payloads of a split archive's volumes in order, checking each
// volume's header (archive ID, number) and checksum as it is read, and ends after the
// volume marked last. Failures are *VolumeError values naming the volume.
type VolumeReader struct {
	next      volumeSource
	index     int
	id        [archive.VolumeIDSize]byte
	cur       io.Reader
	path      string
	header    []byte
	sum       hash.Hash
	remaining uint64
	last      bool
	done      bool
	err       error
}

// OpenVolumes checks that every volume of the split archive base is present, belongs to
// the same archive, is numbered in sequence, and has the size its header declares, then
// returns a reader of the joined archive that also verifies each volume's checksum.
func OpenVolumes(base string) (*VolumeReader, error) {
	if err := checkVolumeSet(base); err != nil {
		return nil, err
	}
	return &VolumeReader{next: func(index int) (io.Reader, string, error) {
		path := VolumePath(base, index)
		f, err := os.Open(path)
		if err != nil {
			return nil, path, err
		}
		return f, path, nil
	}}, nil
}

// NewVolumeStreamReader joins volumes that arrive back to back in one stream, as from
// "cat backup.sarc.*".
func NewVolumeStreamReader(r io.Reader) *VolumeReader {
	return &VolumeReader{next: func(int) (io.Reader, string, error) { return r, "", nil }}
}

// Volumes returns how many volumes have been read and verified completely.
func (vr *VolumeReader) Volumes() int {
	if vr.done {
		return vr.index
	}
	return max(vr.index-1, 0)
}

func (vr *VolumeReader) Read(p []byte) (int, error) {
	for {
		switch {
		case vr.err != nil:
			return 0, vr.err
		case vr.done:
			return 0, io.EOF
		case vr.cur == nil:
			vr.err = vr.openNext()
			continue
		case vr.remaining == 0:
			vr.err = vr.finishVolume()
			continue
		}
		n, err := vr.cur.Read(p[:min(uint64(len(p)), vr.remaining)])
		vr.sum.Write(p[:n])
		vr.remaining -= uint64(n)
		if n > 0 {
			return n, nil
		}
		switch {
		case errors.Is(err, io.EOF):
			vr.err = vr.fail("truncated: the volume ends before its declared length")
		case err != nil:
			vr.err = vr.fail(fmt.Sprintf("read failed: %v", err))
		}
	}
}

// Close closes the volume file being read, if any.
func (vr *VolumeReader) Close() error {
	if c, ok := vr.cur.(io.Closer); ok && vr.path != "" {
		vr.cur = nil
		return c.Close()
	}
	return nil
}

func (vr *VolumeReader) fail(problem string) error {
	return &VolumeError{Index: vr.index, Path: vr.path, Problem: problem}
}

func (vr *VolumeReader) openNext() error {
	vr.index++
	r, path, err := vr.next(vr.index)
	vr.path = path
	if err != nil {
		return vr.fail("missing")
	}
	vr.cur = r
	header := make([]byte, archive.VolumeHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return vr.fail("missing or truncated volume header")
	}
	h, err := archive.ParseVolumeHeader(header)
	if err != nil {
		return vr.fail("not a sarc volume")
	}
	if vr.index == 1 {
		vr.id = h.ArchiveID
	}
	if err := checkVolumeHeader(h, vr.id, vr.index); err != "" {
		return vr.fail(err)
	}
	vr.header, vr.remaining, vr.last, vr.sum = header, h.PayloadLen, h.Last, sha256.New()
	return nil
}

// checkVolumeHeader returns why h cannot be volume index of the archive id, or "".
func checkVolumeHeader(h archive.VolumeHeader, id [archive.VolumeIDSize]byte, index int) string {
	switch {
	case h.ArchiveID != id:
		return "belongs to a different archive"
	case h.Index != uint32(index):
		return fmt.Sprintf("out of order: it is volume %d", h.Index)
	}
	return ""
}

func (vr *VolumeReader) finishVolume() error {
	stored := make([]byte, archive.VolumeChecksumSize)
	if _, err := io.ReadFull(vr.cur, stored); err != nil {
		return vr.fail("truncated: the volume checksum is missing")
	}
	vr.sum.Write(vr.header)
	if subtle.ConstantTimeCompare(vr.sum.Sum(nil), stored) != 1 {
		return vr.fail("corrupted: checksum mismatch")
	}
	if err := vr.Close(); err != nil {
		return vr.fail(fmt.Sprintf("close failed: %v", err))
	}
	vr.cur = nil
	vr.done = vr.last
	return nil
}

// checkVolumeSet reads the header and size of each volume of base up to the one marked
// last, so a missing, foreign, reordered, or truncated volume is reported before any
// data is used.
func checkVolumeSet(base string) error {
	var id [archive.VolumeIDSize]byte
	for index := 1; ; index++ {
		path := VolumePath(base, index)
		h, size, err := readVolumeHeader(path)
		if err != nil {
			return &VolumeError{Index: index, Path: path, Problem: err.Error()}
		}
		if index == 1 {
			id = h.ArchiveID
		}
		if problem := checkVolumeHeader(h, id, index); problem != "" {
			return &VolumeError{Index: index, Path: path, Problem: problem}
		}
		if want := int64(archive.VolumeOverhead) + int64(h.PayloadLen); size != want {
			return &VolumeError{Index: index, Path: path,
				Problem: fmt.Sprintf("truncated or padded: %d bytes, want %d", size, want)}
		}
		if h.Last {
			return nil
		}
	}
}

func readVolumeHeader(path string) (archive.VolumeHeader, int64, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return archive.VolumeHeader{}, 0, errors.New("missing")
	}
	if err != nil {
		return archive.VolumeHeader{}, 0, fmt.Errorf("cannot open: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return archive.VolumeHeader{}, 0, fmt.Errorf("cannot stat: %w", err)
	}
	header := make([]byte, archive.VolumeHeaderSize)
	if _, err := io.ReadFull(f, header); err != nil {
		return archive.VolumeHeader{}, 0, errors.New("truncated volume header")
	}
	h, err := archive.ParseVolumeHeader(header)
	if err != nil {
		return archive.VolumeHeader{}, 0, errors.New("not a sarc volume")
	}
	return h, info.Size(), nil
}
