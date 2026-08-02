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
// (4 * archive.MaxChunkSize ~ 1.1 MB at default block sizes).
const pipelineDepth = 4

type encResult struct {
	block archive.DataBlock
	err   error
}

type macResult struct {
	mac [crypto.HMACSize]byte
	err error
}

// encryptAndStream runs a 2-stage pipeline for a single file:
//
//	Stage 1 (goroutine): read plaintext -> update HMAC -> encrypt -> send DataBlock
//	Stage 2 (caller):    receive DataBlock -> write via send()
//
// While the caller writes block N, the goroutine reads and encrypts block N+1.
// Plaintext buffers are recycled from a sync.Pool; peak in-flight memory is
// pipelineDepth * archive.MaxChunkSize (≈ 1 MB at default settings).
//
// FrameBuilder fb is owned exclusively by the goroutine — no concurrent access.
// Returns the HMAC-SHA256 of the full plaintext.
func encryptAndStream(
	r io.Reader,
	fb *archive.FrameBuilder,
	hmacKey [crypto.KeySize]byte,
	send func(archive.DataBlock) error,
) ([crypto.HMACSize]byte, error) {
	pool := &sync.Pool{
		New: func() any {
			b := make([]byte, archive.MaxChunkSize)
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
			buf := (*bp)[:size]

			n, err := io.ReadFull(r, buf)
			if n > 0 {
				h.Write(buf[:n])
				block, encErr := fb.EncryptChunk(buf[:n])
				pool.Put(bp)
				if encErr != nil {
					blockCh <- encResult{err: encErr}
					macCh <- macResult{err: encErr}
					close(blockCh)
					return
				}
				blockCh <- encResult{block: block}
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
			<-macCh
			return [crypto.HMACSize]byte{}, res.err
		}
		if err := send(res.block); err != nil {
			<-macCh
			return [crypto.HMACSize]byte{}, err
		}
	}

	out := <-macCh
	return out.mac, out.err
}
