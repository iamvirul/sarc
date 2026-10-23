// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"errors"
	"io"

	"github.com/iamvirul/sarc/crypto"
)

// Content-defined chunk size bounds for incremental archives. A cut point depends only
// on nearby content, so an edit changes the chunks around it and no others.
const (
	MinCDCChunkSize = 256 << 10
	AvgCDCChunkSize = 1 << 20
	MaxCDCChunkSize = 4 << 20

	// cdcAvgBits is log2(AvgCDCChunkSize). Normalized chunking (FastCDC) uses a mask with
	// two more bits below the average size and two fewer above it, which narrows the
	// chunk size distribution around the average.
	cdcAvgBits = 20
	cdcMaskS   = ^uint64(1<<(64-(cdcAvgBits+2)) - 1) // top cdcAvgBits+2 bits
	cdcMaskL   = ^uint64(1<<(64-(cdcAvgBits-2)) - 1) // top cdcAvgBits-2 bits
)

// Chunker splits a stream into content-defined chunks with FastCDC over a keyed gear
// table. The table comes from the archive key, so boundaries, and the chunk sizes
// derived from them, differ between archives for the same content.
type Chunker struct {
	r    io.Reader
	gear *[crypto.GearTableSize]uint64
	buf  []byte
	n    int  // valid bytes in buf
	cut  int  // bytes of buf returned by the previous Next
	eof  bool // r is exhausted
}

// NewChunker returns a Chunker reading r with the given gear table.
func NewChunker(r io.Reader, gear *[crypto.GearTableSize]uint64) *Chunker {
	return &Chunker{r: r, gear: gear, buf: make([]byte, MaxCDCChunkSize)}
}

// Next returns the next chunk, valid until the following call, or io.EOF after the
// last one. Every chunk but the last is between MinCDCChunkSize and MaxCDCChunkSize.
func (c *Chunker) Next() ([]byte, error) {
	c.n = copy(c.buf, c.buf[c.cut:c.n])
	c.cut = 0
	for !c.eof && c.n < len(c.buf) {
		m, err := c.r.Read(c.buf[c.n:])
		c.n += m
		if errors.Is(err, io.EOF) {
			c.eof = true
		} else if err != nil {
			return nil, err
		}
	}
	if c.n == 0 {
		return nil, io.EOF
	}
	c.cut = cutPoint(c.buf[:c.n], c.gear)
	return c.buf[:c.cut], nil
}

// cutPoint returns the length of the chunk at the start of data: the first position
// past MinCDCChunkSize where the rolling gear hash matches the mask, or all of data
// (at most MaxCDCChunkSize) when none does.
func cutPoint(data []byte, gear *[crypto.GearTableSize]uint64) int {
	n := len(data)
	if n <= MinCDCChunkSize {
		return n
	}
	normal := min(n, AvgCDCChunkSize)
	var h uint64
	i := MinCDCChunkSize
	for ; i < normal; i++ {
		h = h<<1 + gear[data[i]]
		if h&cdcMaskS == 0 {
			return i + 1
		}
	}
	for ; i < n; i++ {
		h = h<<1 + gear[data[i]]
		if h&cdcMaskL == 0 {
			return i + 1
		}
	}
	return n
}
