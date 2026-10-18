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
	flagCompress, flagNoCompress, flagCompressLevel = false, false, 0
	cmd := &cobra.Command{Use: "archive"}
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
	}{
		{nil, sarcio.CompressionAuto, 3},
		{[]string{"--compress"}, sarcio.CompressionAlways, 3},
		{[]string{"--compress", "--compress-level", "19"}, sarcio.CompressionAlways, 19},
		{[]string{"--compress-level", "1"}, sarcio.CompressionAuto, 1},
		{[]string{"--no-compress"}, sarcio.CompressionNever, 3},
	}
	for _, tc := range cases {
		got, err := parseArchiveFlags(t, tc.args...)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if got.Mode != tc.wantMode || got.Level != tc.wantLevel {
			t.Fatalf("%v: got %v level %d, want %v level %d", tc.args, got.Mode, got.Level, tc.wantMode, tc.wantLevel)
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
