// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/iamvirul/sarc/archive"
)

func writeSizedFile(t *testing.T, dir, name string, size int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, bytes.Repeat([]byte{'a'}, size), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPlanSolidSeparatesCandidatesFromIndividualFiles(t *testing.T) {
	dir := t.TempDir()
	small1 := writeSizedFile(t, dir, "b.txt", 100)
	small2 := writeSizedFile(t, dir, "a.go", 200)
	small3 := writeSizedFile(t, dir, "c.go", 300)
	large := writeSizedFile(t, dir, "large.bin", archive.SolidMemberMaxSize+1)
	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.txt")

	plan := planSolid([]string{small1, large, small2, subdir, small3, missing})

	wantIndividual := []string{large, subdir, missing}
	if len(plan.individual) != len(wantIndividual) {
		t.Fatalf("individual = %v, want %v", plan.individual, wantIndividual)
	}
	for i, p := range wantIndividual {
		if plan.individual[i] != p {
			t.Fatalf("individual[%d] = %s, want %s", i, plan.individual[i], p)
		}
	}
	// Candidates are ordered by extension, stable within an extension.
	want := []string{small2, small3, small1}
	if len(plan.groups) != 1 || len(plan.groups[0]) != len(want) {
		t.Fatalf("groups = %v, want one group %v", plan.groups, want)
	}
	for i, p := range want {
		if plan.groups[0][i] != p {
			t.Fatalf("group[%d] = %s, want %s", i, plan.groups[0][i], p)
		}
	}
}

func TestPlanSolidSplitsGroupsAtMaxStreamSize(t *testing.T) {
	dir := t.TempDir()
	const fileCount = 12
	var paths []string
	for i := 0; i < fileCount; i++ {
		paths = append(paths, writeSizedFile(t, dir, string(rune('a'+i))+".dat", archive.SolidMemberMaxSize))
	}
	plan := planSolid(paths)

	if len(plan.individual) != 0 {
		t.Fatalf("unexpected individual files: %v", plan.individual)
	}
	total := 0
	for _, g := range plan.groups {
		size := 0
		for _, p := range g {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			size += archive.SolidRecordSize(len(info.Name()), int(info.Size()))
		}
		if size > archive.MaxSolidStreamSize {
			t.Fatalf("group stream %d bytes exceeds %d", size, archive.MaxSolidStreamSize)
		}
		total += len(g)
	}
	if len(plan.groups) < 2 || total != fileCount {
		t.Fatalf("got %d groups holding %d files, want >= 2 groups holding %d", len(plan.groups), total, fileCount)
	}
}

func TestPlanSolidStoresLoneCandidateIndividually(t *testing.T) {
	dir := t.TempDir()
	only := writeSizedFile(t, dir, "only.txt", 10)
	large := writeSizedFile(t, dir, "large.bin", archive.SolidMemberMaxSize+1)
	plan := planSolid([]string{only, large})
	if len(plan.groups) != 0 || len(plan.individual) != 2 {
		t.Fatalf("got groups %v individual %v, want no groups", plan.groups, plan.individual)
	}
}

func mustSolidPolicy(t *testing.T) *compressionPolicy {
	t.Helper()
	p, err := newCompressionPolicy(CompressionOptions{Mode: CompressionAuto, Level: archive.DefaultCompressionLevel, Solid: true})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newTestArchiveWriter(t *testing.T) *archive.ArchiveWriter {
	t.Helper()
	aw, err := archive.NewArchiveWriter(&bytes.Buffer{}, archive.Credentials{Passwords: []string{"solid-internal-test"}})
	if err != nil {
		t.Fatal(err)
	}
	return aw
}

func TestBuildSolidEntrySkipsUnreadableMembers(t *testing.T) {
	dir := t.TempDir()
	ok1 := writeSizedFile(t, dir, "ok1.txt", 1000)
	ok2 := writeSizedFile(t, dir, "ok2.txt", 2000)
	vanished := filepath.Join(dir, "vanished.txt")

	entry, members, err := buildSolidEntry(newTestArchiveWriter(t), mustSolidPolicy(t), []string{ok1, vanished, ok2}, NopProgressTracker{})
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil || entry.EntryType != archive.EntryTypeSolid {
		t.Fatalf("want a solid entry, got %+v", entry)
	}
	if len(members) != 3 || members[0].err != nil || members[2].err != nil {
		t.Fatalf("readable members should succeed: %+v", members)
	}
	var ae *ArchiveError
	if !errors.As(members[1].err, &ae) || ae.IsFatal() || ae.Code != ErrCodeReadFailed {
		t.Fatalf("vanished member: want recoverable %s, got %v", ErrCodeReadFailed, members[1].err)
	}
	if members[0].size != 1000 || members[2].size != 2000 {
		t.Fatalf("member sizes %d, %d", members[0].size, members[2].size)
	}
}

func TestBuildSolidEntryWithNoReadableMembersReturnsNoEntry(t *testing.T) {
	dir := t.TempDir()
	entry, members, err := buildSolidEntry(newTestArchiveWriter(t), mustSolidPolicy(t),
		[]string{filepath.Join(dir, "gone1"), filepath.Join(dir, "gone2")}, NopProgressTracker{})
	if err != nil {
		t.Fatal(err)
	}
	if entry != nil {
		t.Fatal("built an entry with no members")
	}
	for _, m := range members {
		if m.err == nil {
			t.Fatal("missing member reported success")
		}
	}
}

func TestSolidCodecForWithoutSolidCompressorIsNone(t *testing.T) {
	if got := mustPolicy(t, CompressionAlways).solidCodecFor(bytes.Repeat([]byte("x"), 4096)); got != archive.CodecNone {
		t.Fatalf("got %v, want none without a solid compressor", got)
	}
}

func TestSolidCodecForFollowsMode(t *testing.T) {
	text := bytes.Repeat([]byte("compressible solid stream "), 4096)
	cases := map[CompressionMode]archive.Codec{
		CompressionAuto:   archive.CodecZstd,
		CompressionAlways: archive.CodecZstd,
		CompressionNever:  archive.CodecNone,
	}
	for mode, want := range cases {
		p, err := newCompressionPolicy(CompressionOptions{Mode: mode, Level: 3, Solid: true})
		if err != nil {
			t.Fatal(err)
		}
		if got := p.solidCodecFor(text); got != want {
			t.Fatalf("%v: got %v, want %v", mode, got, want)
		}
		if want == archive.CodecZstd && p.solidCompressor == nil {
			t.Fatalf("%v: solid compressor not built", mode)
		}
	}
}
