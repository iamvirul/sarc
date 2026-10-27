// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"io"

	"github.com/iamvirul/sarc/archive"
)

// directoryBuilder collects the directory of a one-pass archive as its entries are
// written. Once the directory would exceed archive.MaxDirectorySize it stops collecting
// and the archive is written without one, so memory stays bounded.
type directoryBuilder struct {
	plaintext []byte
	full      bool
}

func newDirectoryBuilder() *directoryBuilder {
	return &directoryBuilder{plaintext: archive.NewDirectory()}
}

// add appends r to the directory.
func (d *directoryBuilder) add(r archive.DirectoryRecord) error {
	if d.full {
		return nil
	}
	out, err := archive.AppendDirectoryRecord(d.plaintext, r)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "record directory entry", err)
	}
	if len(out) > archive.MaxDirectorySize {
		d.plaintext, d.full = nil, true
		return nil
	}
	d.plaintext = out
	return nil
}

// entrySummary is what a file entry's sealed metadata and trailer record, for its
// directory record.
type entrySummary struct {
	bucket   archive.SizeBucket
	codec    archive.Codec
	original int64 // plaintext size
}

// specialSummary summarizes a data-free entry: a directory or link.
var specialSummary = entrySummary{bucket: archive.BucketTiny, codec: archive.CodecNone}

// addEntry records in, summarized by sum, as the entry aw wrote last.
func (d *directoryBuilder) addEntry(aw *archive.ArchiveWriter, in inputFile, sum entrySummary) error {
	offset, stored := aw.LastEntry()
	return d.add(archive.DirectoryRecord{
		Offset:       uint64(offset),
		Name:         in.name,
		Attributes:   in.attrs,
		SizeBucket:   sum.bucket,
		Codec:        sum.codec,
		OriginalSize: uint64(sum.original),
		StoredSize:   uint64(stored),
	})
}

// addSolid records the packed members of the solid group aw wrote last.
func (d *directoryBuilder) addSolid(aw *archive.ArchiveWriter, members []solidMemberResult) error {
	offset, _ := aw.LastEntry()
	for _, m := range members {
		if m.err != nil {
			continue
		}
		err := d.add(archive.DirectoryRecord{
			Offset:       uint64(offset),
			Name:         m.name,
			Attributes:   m.attrs,
			SizeBucket:   archive.BucketizeSize(m.size),
			Codec:        m.codec,
			Solid:        true,
			OriginalSize: uint64(m.size),
			StoredSize:   uint64(m.stored),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// write seals the directory as an entry and writes it and its locator to aw, unless it
// outgrew archive.MaxDirectorySize.
func (d *directoryBuilder) write(aw *archive.ArchiveWriter) error {
	if d.full {
		return nil
	}
	offset := aw.Offset()
	entry, err := sealPayloadEntry(aw, archive.EntryTypeDirectory, archive.CodecNone, d.plaintext, d.plaintext)
	if err != nil {
		return err
	}
	if err := aw.WriteFileEntry(entry); err != nil {
		return fatal(ErrCodeWriteFailed, "write directory", err)
	}
	if err := aw.WriteDirectoryLocator(offset); err != nil {
		return fatal(ErrCodeWriteFailed, "write directory locator", err)
	}
	return nil
}

// readDirectory reads and authenticates the directory of the Version2 one-pass archive
// in the first size bytes of ra, which may end with a signature block. It reports false
// when the archive has no directory: one written before directories existed, or one
// whose directory outgrew archive.MaxDirectorySize.
func readDirectory(ra io.ReaderAt, size int64, keys *archive.KeySchedule, header headerInfo) ([]archive.DirectoryRecord, bool, error) {
	proper, _, err := splitSignature(ra, size)
	if err != nil {
		return nil, false, err
	}
	tail := proper - int64(archive.DirectoryTailSize)
	if tail < header.end() {
		return nil, false, nil
	}
	buf := make([]byte, archive.DirectoryTailSize)
	if _, err := ra.ReadAt(buf, tail); err != nil {
		return nil, false, fatal(ErrCodeReadFailed, "read archive tail", err)
	}
	// Without a directory these bytes end the last entry's trailer, which matches the
	// locator's type and magic with negligible probability.
	offset, err := archive.ParseDirectoryLocator(buf[:archive.DirectoryLocatorSize])
	if err != nil {
		return nil, false, nil
	}
	if buf[archive.DirectoryLocatorSize] != archive.EntryTypeEnd {
		return nil, false, fatal(ErrCodeIntegrityFail, "damaged archive tail", nil)
	}
	if offset < uint64(header.end()) || offset >= uint64(tail) {
		return nil, false, fatal(ErrCodeIntegrityFail, "directory locator points outside the archive", nil)
	}
	sub, _ := entryReaderAt(ra, tail, int64(offset))
	var entryType [1]byte
	if _, err := io.ReadFull(sub.r, entryType[:]); err != nil {
		return nil, false, fatal(ErrCodeTruncated, "read directory", err)
	}
	if entryType[0] != archive.EntryTypeDirectory {
		return nil, false, fatal(ErrCodeIntegrityFail, "expected a directory entry", nil)
	}
	plaintext, err := sub.readPayloadBody(keys, archive.MaxDirectorySize, "directory")
	if err != nil {
		return nil, false, err
	}
	records, err := archive.ParseDirectory(plaintext)
	if err != nil {
		return nil, false, fatal(ErrCodeIntegrityFail, "parse directory", err)
	}
	for _, r := range records {
		if r.Offset < uint64(header.end()) || r.Offset >= offset {
			return nil, false, fatal(ErrCodeIntegrityFail, "directory entry points outside the archive", nil)
		}
	}
	return records, true, nil
}

// directoryListing returns the listing of records, as scanning the entries would.
func directoryListing(records []archive.DirectoryRecord) []ListResult {
	results := make([]ListResult, 0, len(records))
	for _, r := range records {
		attrs := r.Attributes
		results = append(results, withAttributes(ListResult{
			Filename:      r.Name,
			SizeBucket:    bucketName(r.SizeBucket),
			Codec:         r.Codec.String(),
			Solid:         r.Solid,
			OriginalBytes: int64(r.OriginalSize),
			StoredBytes:   int64(r.StoredSize),
		}, &attrs, 0))
	}
	return results
}

// skipDirectory consumes a directory entry, or the rest of a locator, whose type byte
// was just read, so sequential readers pass over both.
func (se *SafeExtractor) skipDirectory(keys *archive.KeySchedule, entryType byte) error {
	if entryType == archive.EntryTypeDirectoryLocator {
		rest := make([]byte, archive.DirectoryLocatorSize-1)
		if _, err := io.ReadFull(se.r, rest); err != nil {
			return fatal(ErrCodeTruncated, "read directory locator", err)
		}
		if _, err := archive.ParseDirectoryLocator(append([]byte{entryType}, rest...)); err != nil {
			return fatal(ErrCodeIntegrityFail, "damaged directory locator", err)
		}
		return nil
	}
	if _, err := se.readEntryHead(keys); err != nil {
		return fatal(ErrCodeIntegrityFail, "damaged directory", err)
	}
	if err := se.skipEntryBody(nil); err != nil {
		return fatal(ErrCodeIntegrityFail, "damaged directory", err)
	}
	return nil
}
