// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// sizeUnits follows GNU split: K, M, G, T and KiB..TiB are powers of 1024; KB, MB, GB,
// and TB are powers of 1000, so "2GB" stays under a 2 GB limit of either kind.
var sizeUnits = map[string]float64{
	"": 1, "B": 1,
	"K": 1 << 10, "KIB": 1 << 10, "KB": 1e3,
	"M": 1 << 20, "MIB": 1 << 20, "MB": 1e6,
	"G": 1 << 30, "GIB": 1 << 30, "GB": 1e9,
	"T": 1 << 40, "TIB": 1 << 40, "TB": 1e12,
}

// decimalNumber is the number part of a size: digits with an optional fraction.
var decimalNumber = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// parseSize parses a byte count such as "2GB", "700MiB", "1.5G", or "65536".
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	i := len(s)
	for i > 0 && (s[i-1] < '0' || s[i-1] > '9') && s[i-1] != '.' {
		i--
	}
	unit, ok := sizeUnits[strings.ToUpper(strings.TrimSpace(s[i:]))]
	number, err := strconv.ParseFloat(s[:i], 64)
	if !ok || err != nil || !decimalNumber.MatchString(s[:i]) || number <= 0 {
		return 0, fmt.Errorf("invalid size %q: use a number with an optional unit, such as 2GB, 700MiB, or 1.5G", s)
	}
	bytes := number * unit
	if bytes > math.MaxInt64/2 {
		return 0, fmt.Errorf("size %q is too large", s)
	}
	return int64(bytes), nil
}
