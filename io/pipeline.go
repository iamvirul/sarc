// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	stdhmac "crypto/hmac"
	"crypto/sha256"
	"io"
	"sync"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// pipelineDepth is the number of DataBlocks buffered between the encrypt and write stages.
// Four blocks in flight keeps the writer busy without materially growing memory use
// (4 * bufSize ~ 1.1 MB at default block sizes).
const pipelineDepth = 4

// bufSize is the per-buffer capacity in the pool.
// Layout: [plaintext 0..n][ciphertext n..n+n+GCMTagSize].
// A single allocation covers both regions, eliminating the per-block ciphertext malloc.
const bufSize = archive.MaxChunkSize + crypto.GCMTagSize

type encResult struct {
	block archive.DataBlock
	buf   *[]byte // combined buffer; return to pool after the DataBlock has been written
	err   error
}

type macResult struct {
	mac [crypto.HMACSize]byte
	err error
}

// encryptAndStream runs a 2-stage pipeline for a single file:
//
//	Stage 1 (goroutine): read plaintext -> update HMAC -> encrypt in-place -> send DataBlock
//	Stage 2 (caller):    receive DataBlock -> write via send() -> return buffer to pool
//
// The combined plaintext+ciphertext buffer is pooled so steady-state allocation
// on the hot path is zero. Peak in-flight memory is pipelineDepth*bufSize (≈ 1.1 MB).
//
// FrameBuilder fb is owned exclusively by the goroutine. Returns the HMAC-SHA256
// of the full plaintext.
func encryptAndStream(
	r io.Reader,
	fb *archive.FrameBuilder,
	hmacKey [crypto.KeySize]byte,
	send func(archive.DataBlock) error,
) ([crypto.HMACSize]byte, error) {
	pool := &sync.Pool{
		New: func() any {
			b := make([]byte, bufSize)
			return &b
		},
	}

	blockCh := make(chan encResult, pipelineDepth)
	macCh := make(chan macResult, 1)

	go func() {
		h := stdhmac.New(sha256.New, hmacKey[:])
		for {
			size := fb.NextChunkSize()
			bp := pool.Get().(*[]byte)
			b := *bp

			n, err := io.ReadFull(r, b[:size])
			if n > 0 {
				h.Write(b[:n])
				// Seal into b[n:] — non-overlapping with plaintext b[:n], no allocation.
				block, encErr := fb.EncryptChunkInto(b[:n], b[n:])
				if encErr != nil {
					pool.Put(bp)
					blockCh <- encResult{err: encErr}
					macCh <- macResult{err: encErr}
					close(blockCh)
					return
				}
				blockCh <- encResult{block: block, buf: bp}
			} else {
				pool.Put(bp)
			}
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			if err != nil {
				blockCh <- encResult{err: err}
				macCh <- macResult{err: err}
				close(blockCh)
				return
			}
		}

		var sum [crypto.HMACSize]byte
		copy(sum[:], h.Sum(nil))
		macCh <- macResult{mac: sum}
		close(blockCh)
	}()

	for res := range blockCh {
		if res.err != nil {
			if res.buf != nil {
				pool.Put(res.buf)
			}
			<-macCh
			return [crypto.HMACSize]byte{}, res.err
		}
		if err := send(res.block); err != nil {
			if res.buf != nil {
				pool.Put(res.buf)
			}
			<-macCh
			return [crypto.HMACSize]byte{}, err
		}
		// send returned: ciphertext (sub-slice of *res.buf) is fully written.
		if res.buf != nil {
			pool.Put(res.buf)
		}
	}

	out := <-macCh
	return out.mac, out.err
}
