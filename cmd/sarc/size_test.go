// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import "testing"

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{
		"65536":  65536,
		"2GB":    2_000_000_000,
		"2gb":    2_000_000_000,
		"2G":     2 << 30,
		"2GiB":   2 << 30,
		"700MiB": 700 << 20,
		"700MB":  700_000_000,
		"1.5G":   3 << 29,
		"64K":    64 << 10,
		"10 MB":  10_000_000,
		"1TB":    1_000_000_000_000,
		"512B":   512,
		" 3M ":   3 << 20,
	} {
		got, err := parseSize(in)
		if err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "GB", "-1GB", "0", "2XB", "1e3GB", "abc", "1..5G", "99999999999TB"} {
		if got, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) = %d, want an error", in, got)
		}
	}
}
