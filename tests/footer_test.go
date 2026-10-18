// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"testing"

	"github.com/iamvirul/sarc/archive"
	sarcio "github.com/iamvirul/sarc/io"
)

// footerSize is the byte length of the archive footer (HMAC + reserved).
const footerSize = archive.HMACSize + archive.ReservedSize

// TestExtractFooterStartingWithEntryTypeByte forces the footer HMAC to begin with
// EntryTypeFile (0x01), which happens naturally for ~1 in 256 archives. The extractor
// must still see exactly one entry rather than parsing the footer as a phantom entry.
// The archive HMAC is only checked by `sarc verify`, so patching it here simulates
// the collision without changing what the extractor reads.
func TestExtractFooterStartingWithEntryTypeByte(t *testing.T) {
	data := archiveOneFile(t, "one.txt")
	data[len(data)-footerSize] = archive.EntryTypeFile

	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), singleEntryPassword, nil).Extract(t.TempDir())
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(results) != 1 || !results[0].OK {
		t.Fatalf("got %d results (%+v), want exactly 1 successful entry", len(results), results)
	}
}

func TestListFooterStartingWithEntryTypeByte(t *testing.T) {
	data := archiveOneFile(t, "one.txt")
	data[len(data)-footerSize] = archive.EntryTypeFile

	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), singleEntryPassword, nil).List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(results) != 1 || results[0].Filename != "one.txt" {
		t.Fatalf("got %+v, want exactly one entry named one.txt", results)
	}
}

func TestVersion2ArchiveEndsWithEndMarker(t *testing.T) {
	data := archiveOneFile(t, "one.txt")
	if got := data[len(data)-footerSize-1]; got != archive.EntryTypeEnd {
		t.Fatalf("byte before footer = 0x%02x, want EntryTypeEnd 0x%02x", got, archive.EntryTypeEnd)
	}
}

func TestExtractTruncatedBeforeEndMarkerIsFatal(t *testing.T) {
	data := archiveOneFile(t, "one.txt")
	truncated := data[:len(data)-footerSize-1]

	results, err := sarcio.NewSafeExtractor(bytes.NewReader(truncated), singleEntryPassword, nil).Extract(t.TempDir())
	requireFatal(t, err, sarcio.ErrCodeTruncated)
	if len(results) != 1 || !results[0].OK {
		t.Fatalf("entries before the truncation should still be reported, got %+v", results)
	}
}

func TestExtractUnexpectedEntryTypeIsFatal(t *testing.T) {
	data := archiveOneFile(t, "one.txt")
	data[len(data)-footerSize-1] = 0x7F

	_, err := sarcio.NewSafeExtractor(bytes.NewReader(data), singleEntryPassword, nil).Extract(t.TempDir())
	requireFatal(t, err, sarcio.ErrCodeIntegrityFail)
}

func TestListTruncatedBeforeEndMarkerIsFatal(t *testing.T) {
	data := archiveOneFile(t, "one.txt")
	truncated := data[:len(data)-footerSize-1]

	_, err := sarcio.NewSafeExtractor(bytes.NewReader(truncated), singleEntryPassword, nil).List()
	requireFatal(t, err, sarcio.ErrCodeTruncated)
}
