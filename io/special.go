// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// writeSpecialEntries writes a data-free entry for each directory, symlink, and hard
// link, and records each in dir. They follow every file, so a hard link's target always
// precedes it and a directory's attributes can be applied after its contents are
// extracted.
func writeSpecialEntries(aw *archive.ArchiveWriter, dir *directoryBuilder, special []inputFile, progress ProgressTracker) error {
	for _, in := range special {
		entry, err := sealSpecialEntry(aw, in)
		if err != nil {
			return err
		}
		if err := aw.WriteFileEntry(entry); err != nil {
			return fatal(ErrCodeWriteFailed, "write entry", err)
		}
		if err := dir.addEntry(aw, in, specialSummary); err != nil {
			return err
		}
		progress.FileFinished(in.name)
	}
	return nil
}

// sealSpecialEntry seals in as a file entry with no data blocks: its name and
// attributes, including any link target, are inside the sealed metadata.
func sealSpecialEntry(aw *archive.ArchiveWriter, in inputFile) (archive.FileEntry, error) {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "generate salt", err)
	}
	fileKey, err := aw.DeriveFileKey(salt)
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "derive file key", err)
	}
	fb, err := archive.NewFrameBuilder(fileKey)
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "init frame builder", err)
	}
	frameHdr, err := fb.FrameHeader()
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "frame header", err)
	}
	encName, err := encryptFilename(in.name, fileKey)
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "encrypt filename", err)
	}
	mm, err := archive.NewMetadataManager(fileKey)
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "init metadata manager", err)
	}
	attrs := in.attrs
	meta, err := mm.Seal(archive.PlaintextMetadata{
		EncryptedFilename: encName,
		SizeBucket:        archive.BucketTiny,
		Permissions:       attrs.Mode & 0o777,
		Codec:             archive.CodecNone,
		Attributes:        &attrs,
	})
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "seal metadata", err)
	}
	interPad, err := fb.InterBlockPadding()
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "inter-block padding", err)
	}
	trailer, err := fb.BuildTrailer(crypto.ComputeHMAC(fileKey, nil), 0)
	if err != nil {
		return archive.FileEntry{}, fatal(ErrCodeWriteFailed, "build trailer", err)
	}
	return archive.FileEntry{
		EntryType: archive.EntryTypeFile, EntrySalt: salt, FrameHdr: frameHdr,
		Metadata: meta, InterBlockPad: interPad, Trailer: trailer,
	}, nil
}
