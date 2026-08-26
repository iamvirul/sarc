// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"os"
	"testing"
)

func TestEstimateArchiveSize(t *testing.T) {
	cases := []struct {
		input int64
		want  int64
	}{
		{0, 0},
		{1000, 1120},
		{1_000_000, 1_120_000},
	}
	for _, c := range cases {
		if got := estimateArchiveSize(c.input); got != c.want {
			t.Errorf("estimateArchiveSize(%d) = %d, want %d", c.input, got, c.want)
		}
	}
}

func TestPreallocateRejectsNonPositiveSize(t *testing.T) {
	f, err := os.CreateTemp("", "sarc-preallocate-test-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	if err := preallocate(f, 0); err == nil {
		t.Fatal("expected error preallocating zero bytes, got nil")
	}
	if err := preallocate(f, -1); err == nil {
		t.Fatal("expected error preallocating a negative size, got nil")
	}
}

// TestPreallocateOutputDoesNotChangeReportedSize verifies the defining property this
// optimisation depends on: reserving space for a file must not change its logical
// size (stat), since that's what keeps the final archive free of zero-padding without
// needing a truncate step. On platforms without a preallocate implementation,
// PreallocateOutput returns an error and the file is untouched, which also satisfies
// this property trivially.
func TestPreallocateOutputDoesNotChangeReportedSize(t *testing.T) {
	f, err := os.CreateTemp("", "sarc-preallocate-test-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	if err := PreallocateOutput(f, 64*1024*1024); err != nil {
		t.Logf("PreallocateOutput not supported on this platform/filesystem: %v", err)
	}

	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("file size after preallocation = %d, want 0 (no writes have happened yet)", info.Size())
	}
}

// TestPreallocateOutputThenWriteExactSize verifies that after preallocating and then
// writing the actual archive bytes, the file's final size is exactly the number of
// bytes written, with no leftover zero-padding from the (larger, estimated)
// preallocation reservation.
func TestPreallocateOutputThenWriteExactSize(t *testing.T) {
	f, err := os.CreateTemp("", "sarc-preallocate-test-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	// Reserve space for far more than we'll actually write, to prove the excess
	// reservation never leaks into the final file size.
	if err := PreallocateOutput(f, 64*1024*1024); err != nil {
		t.Logf("PreallocateOutput not supported on this platform/filesystem: %v", err)
	}

	const actual = 12345
	data := make([]byte, actual)
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}

	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != actual {
		t.Fatalf("file size after writing %d bytes = %d, want %d (no zero-padding)", actual, info.Size(), actual)
	}
}
