// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"testing"
)

// routeChunks feeds stream to a router in pieces of feedSize bytes and returns the
// chunks it delivered by chunk number.
func routeChunks(t *testing.T, chunks []chunkLocation, needed []uint64, stream []byte, feedSize int) (map[uint64][]byte, error) {
	t.Helper()
	got := map[uint64][]byte{}
	r := chunkRouter{chunks: chunks, needed: needed, deliver: func(n uint64, stored []byte) error {
		got[n] = bytes.Clone(stored)
		return nil
	}}
	for len(stream) > 0 {
		n := min(feedSize, len(stream))
		if err := r.feed(stream[:n]); err != nil {
			return got, err
		}
		stream = stream[n:]
	}
	if r.idx != len(needed) {
		t.Fatalf("router delivered %d of %d chunks", r.idx, len(needed))
	}
	return got, nil
}

func TestChunkRouterDeliversNeededChunksAcrossFeeds(t *testing.T) {
	stream := []byte("aaaaBBBBBBccccDDDeeeee")
	chunks := []chunkLocation{
		{offset: 0, stored: 4},  // aaaa (not needed)
		{offset: 4, stored: 6},  // BBBBBB
		{offset: 10, stored: 4}, // cccc (not needed)
		{offset: 14, stored: 3}, // DDD
		{offset: 17, stored: 5}, // eeeee
	}
	for _, feed := range []int{1, 3, 7, len(stream)} {
		got, err := routeChunks(t, chunks, []uint64{1, 3, 4}, stream, feed)
		if err != nil {
			t.Fatalf("feed %d: %v", feed, err)
		}
		want := map[uint64]string{1: "BBBBBB", 3: "DDD", 4: "eeeee"}
		for n, w := range want {
			if string(got[n]) != w {
				t.Fatalf("feed %d: chunk %d = %q, want %q", feed, n, got[n], w)
			}
		}
	}
}

func TestChunkRouterRejectsOverlappingChunks(t *testing.T) {
	chunks := []chunkLocation{{offset: 0, stored: 6}, {offset: 4, stored: 4}}
	r := chunkRouter{chunks: chunks, needed: []uint64{0, 1}, deliver: func(uint64, []byte) error { return nil }}
	if err := r.feed(make([]byte, 10)); err == nil || r.err == nil {
		t.Fatal("overlapping chunks accepted")
	}
}

func TestUnderAny(t *testing.T) {
	prefixes := []string{"data/logs", "solo.txt"}
	for name, want := range map[string]bool{
		"data/logs":          true,
		"data/logs/2026.log": true,
		"data/logs2/x":       false,
		"data/log":           false,
		"solo.txt":           true,
		"solo.txt.bak":       false,
	} {
		if got := underAny(name, prefixes); got != want {
			t.Errorf("underAny(%q) = %v, want %v", name, got, want)
		}
	}
}
