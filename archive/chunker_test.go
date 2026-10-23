// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

func gearFor(t *testing.T, seed byte) *[crypto.GearTableSize]uint64 {
	t.Helper()
	var master [crypto.KeySize]byte
	master[0] = seed
	gear, err := crypto.DeriveGearTable(master)
	if err != nil {
		t.Fatal(err)
	}
	return &gear
}

func chunkAll(t *testing.T, data []byte, gear *[crypto.GearTableSize]uint64) [][]byte {
	t.Helper()
	c := archive.NewChunker(bytes.NewReader(data), gear)
	var chunks [][]byte
	for {
		chunk, err := c.Next()
		if errors.Is(err, io.EOF) {
			return chunks
		}
		if err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, bytes.Clone(chunk))
	}
}

func randomData(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestChunkerReassemblesAndRespectsBounds(t *testing.T) {
	data := randomData(t, 24<<20+12345)
	chunks := chunkAll(t, data, gearFor(t, 1))
	if got := bytes.Join(chunks, nil); !bytes.Equal(got, data) {
		t.Fatal("chunks do not reassemble the input")
	}
	for i, c := range chunks {
		last := i == len(chunks)-1
		if len(c) > archive.MaxCDCChunkSize || (!last && len(c) < archive.MinCDCChunkSize) {
			t.Fatalf("chunk %d is %d bytes", i, len(c))
		}
	}
	if avg := len(data) / len(chunks); avg < archive.AvgCDCChunkSize/2 || avg > archive.AvgCDCChunkSize*2 {
		t.Fatalf("average chunk %d bytes, want near %d", avg, archive.AvgCDCChunkSize)
	}
}

func TestChunkerEdgeSizes(t *testing.T) {
	gear := gearFor(t, 1)
	if chunks := chunkAll(t, nil, gear); len(chunks) != 0 {
		t.Fatalf("empty input gave %d chunks", len(chunks))
	}
	small := randomData(t, 1000)
	if chunks := chunkAll(t, small, gear); len(chunks) != 1 || !bytes.Equal(chunks[0], small) {
		t.Fatal("small input is not one chunk")
	}
	zeros := make([]byte, 3*archive.MaxCDCChunkSize)
	chunks := chunkAll(t, zeros, gear)
	if len(chunks) != 3 {
		t.Fatalf("featureless input gave %d chunks, want 3 of the maximum size", len(chunks))
	}
}

// TestChunkerLocalEditChangesFewChunks flips one byte in the middle of a stream; only
// the chunks around the edit may change.
func TestChunkerLocalEditChangesFewChunks(t *testing.T) {
	gear := gearFor(t, 1)
	data := randomData(t, 32<<20)
	before := chunkAll(t, data, gear)
	edited := bytes.Clone(data)
	edited[len(edited)/2] ^= 0xFF
	after := chunkAll(t, edited, gear)

	known := map[string]bool{}
	for _, c := range before {
		known[string(c)] = true
	}
	changed := 0
	for _, c := range after {
		if !known[string(c)] {
			changed++
		}
	}
	if changed == 0 || changed > 2 {
		t.Fatalf("%d of %d chunks changed after a one-byte edit, want 1 or 2", changed, len(after))
	}
}

// TestChunkerBoundariesDependOnKey checks two keys cut the same content differently, so
// chunk sizes cannot be matched across archives.
func TestChunkerBoundariesDependOnKey(t *testing.T) {
	data := randomData(t, 16<<20)
	a, b := chunkAll(t, data, gearFor(t, 1)), chunkAll(t, data, gearFor(t, 2))
	sizesA := map[int]bool{}
	for _, c := range a[:len(a)-1] {
		sizesA[len(c)] = true
	}
	shared := 0
	for _, c := range b[:len(b)-1] {
		if sizesA[len(c)] {
			shared++
		}
	}
	if shared > 1 {
		t.Fatalf("%d chunk sizes shared between keys", shared)
	}
}

// oneByteReader returns one byte per Read, exercising short reads.
type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) { return o.r.Read(p[:min(len(p), 1)]) }

func TestChunkerHandlesShortReads(t *testing.T) {
	gear := gearFor(t, 3)
	data := randomData(t, 3<<20)
	want := chunkAll(t, data, gear)
	c := archive.NewChunker(oneByteReader{bytes.NewReader(data)}, gear)
	for i := 0; ; i++ {
		chunk, err := c.Next()
		if errors.Is(err, io.EOF) {
			if i != len(want) {
				t.Fatalf("got %d chunks, want %d", i, len(want))
			}
			return
		}
		if err != nil || !bytes.Equal(chunk, want[i]) {
			t.Fatalf("chunk %d differs under short reads (%v)", i, err)
		}
	}
}
