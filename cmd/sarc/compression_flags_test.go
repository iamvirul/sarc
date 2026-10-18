// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"

	sarcio "github.com/iamvirul/sarc/io"
)

// parseArchiveFlags parses args with a fresh archive flag set bound to the package
// flag variables and returns the resulting compression options.
func parseArchiveFlags(t *testing.T, args ...string) (sarcio.CompressionOptions, error) {
	t.Helper()
	flagCompress, flagNoCompress, flagCompressLevel, flagSolid = false, false, 0, false
	cmd := &cobra.Command{Use: "archive"}
	cmd.Flags().BoolVar(&flagSolid, "solid", false, "")
	cmd.Flags().BoolVar(&flagCompress, "compress", false, "")
	cmd.Flags().BoolVar(&flagNoCompress, "no-compress", false, "")
	cmd.Flags().IntVar(&flagCompressLevel, "compress-level", 3, "")
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatal(err)
	}
	return compressionOptions(cmd)
}

func TestCompressionOptionsFromFlags(t *testing.T) {
	cases := []struct {
		args      []string
		wantMode  sarcio.CompressionMode
		wantLevel int
		wantSolid bool
	}{
		{nil, sarcio.CompressionAuto, 3, false},
		{[]string{"--compress"}, sarcio.CompressionAlways, 3, false},
		{[]string{"--compress", "--compress-level", "19"}, sarcio.CompressionAlways, 19, false},
		{[]string{"--compress-level", "1"}, sarcio.CompressionAuto, 1, false},
		{[]string{"--no-compress"}, sarcio.CompressionNever, 3, false},
		{[]string{"--solid"}, sarcio.CompressionAuto, 3, true},
		{[]string{"--solid", "--compress-level", "19"}, sarcio.CompressionAuto, 19, true},
	}
	for _, tc := range cases {
		got, err := parseArchiveFlags(t, tc.args...)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if got.Mode != tc.wantMode || got.Level != tc.wantLevel || got.Solid != tc.wantSolid {
			t.Fatalf("%v: got %+v, want mode %v level %d solid %v", tc.args, got, tc.wantMode, tc.wantLevel, tc.wantSolid)
		}
	}
}

func TestCompressionOptionsRejectsInvalidFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--compress-level", "0"},
		{"--compress-level", "23"},
		{"--no-compress", "--compress-level", "5"},
	} {
		if _, err := parseArchiveFlags(t, args...); err == nil {
			t.Fatalf("%v: accepted invalid flags", args)
		}
	}
}

func TestFormatRatio(t *testing.T) {
	cases := []struct {
		r    sarcio.ListResult
		want string
	}{
		{sarcio.ListResult{OriginalBytes: 1000, StoredBytes: 314}, "31.4%"},
		{sarcio.ListResult{OriginalBytes: 1000, StoredBytes: 1000}, "100.0%"},
		{sarcio.ListResult{OriginalBytes: 2_000_000, StoredBytes: 300}, "<0.1%"},
		{sarcio.ListResult{OriginalBytes: 0, StoredBytes: 0}, "-"},
		{sarcio.ListResult{OriginalBytes: 10, StoredBytes: 5, Err: errors.New("boom")}, "-"},
	}
	for _, tc := range cases {
		if got := formatRatio(tc.r); got != tc.want {
			t.Fatalf("formatRatio(%+v) = %q, want %q", tc.r, got, tc.want)
		}
	}
}

func TestFormatCodec(t *testing.T) {
	if got := formatCodec(sarcio.ListResult{Codec: "zstd", Solid: true}); got != "zstd+solid" {
		t.Fatalf("got %q, want zstd+solid", got)
	}
	if got := formatCodec(sarcio.ListResult{Codec: "none"}); got != "none" {
		t.Fatalf("got %q, want none", got)
	}
}
