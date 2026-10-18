// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	stdhmac "crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"sync"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// pipelineDepth is the number of DataBlocks buffered between the encrypt and write stages.
// Four blocks in flight keeps the writer busy without materially growing memory use
// (4 * bufSize ~ 2.3 MB at default block sizes).
const pipelineDepth = 4

// bufSize is the per-buffer capacity in the pool.
// Layout: [plaintext 0..n][ciphertext n..n+payload+GCMTagSize], where payload is n bytes
// uncompressed or at most archive.MaxPayloadSize zstd-encoded. A single allocation covers
// both regions, eliminating the per-block ciphertext malloc.
const bufSize = archive.MaxChunkSize + archive.MaxPayloadSize + crypto.GCMTagSize

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
// on the hot path is zero. Peak in-flight memory is pipelineDepth*bufSize (≈ 2.3 MB).
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

// parallelPipelineDepth is the number of in-flight blocks buffered per worker.
// Total buffers in flight are bounded by workers*parallelPipelineDepth, so peak
// memory stays a small, fixed multiple of bufSize regardless of file size.
const parallelPipelineDepth = 4

type parallelJob struct {
	buf    *[]byte
	n      int
	nonce  [crypto.NonceSize]byte
	result chan parallelResult
}

type parallelResult struct {
	block archive.DataBlock
	buf   *[]byte
}

type dispatchOutcome struct {
	mac [crypto.HMACSize]byte
	err error
}

var errDispatchCanceled = errors.New("io: encryption pipeline canceled after write failure")

// encryptAndStreamParallel is a multi-worker variant of encryptAndStream: a single
// dispatcher goroutine reads plaintext, updates the running HMAC, and draws nonces
// (all of which must happen on one goroutine, since both the reader and the
// FrameBuilder's BufferedRand are single-threaded by contract). The actual AES-256-GCM
// seal for each chunk, the CPU-bound step, is handed off to one of `workers` goroutines
// sharing the FrameBuilder's EncryptionManager, which is safe for concurrent Seal calls
// given distinct nonces (see EncryptBlockWithNonceInto).
//
// Output order is preserved via a channel-of-channels: the dispatcher enqueues each
// job's dedicated result channel onto `ordered` in dispatch order, so the caller drains
// results in that same order regardless of which worker finishes first.
//
// Falls back to the sequential single-worker pipeline when workers < 2.
func encryptAndStreamParallel(
	r io.Reader,
	fb *archive.FrameBuilder,
	hmacKey [crypto.KeySize]byte,
	workers int,
	send func(archive.DataBlock) error,
) ([crypto.HMACSize]byte, error) {
	if workers < 2 {
		return encryptAndStream(r, fb, hmacKey, send)
	}

	bufCount := workers * parallelPipelineDepth
	freeList := make(chan *[]byte, bufCount)
	for i := 0; i < bufCount; i++ {
		b := make([]byte, bufSize)
		freeList <- &b
	}

	jobs := make(chan parallelJob, bufCount)
	ordered := make(chan chan parallelResult, bufCount)
	cancel := make(chan struct{})
	var cancelOnce sync.Once

	var workerWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for j := range jobs {
				block := fb.EncryptChunkWithNonceInto(j.nonce, (*j.buf)[:j.n], (*j.buf)[j.n:])
				j.result <- parallelResult{block: block, buf: j.buf}
			}
		}()
	}

	outcomeCh := make(chan dispatchOutcome, 1)
	go func() {
		defer close(jobs)
		defer close(ordered)
		h := stdhmac.New(sha256.New, hmacKey[:])
		for {
			select {
			case <-cancel:
				outcomeCh <- dispatchOutcome{err: errDispatchCanceled}
				return
			default:
			}

			size := fb.NextChunkSize()
			bp := <-freeList
			b := *bp

			n, err := io.ReadFull(r, b[:size])
			if n > 0 {
				h.Write(b[:n])
				nonce, nerr := fb.NextNonce()
				if nerr != nil {
					freeList <- bp
					outcomeCh <- dispatchOutcome{err: nerr}
					return
				}
				resCh := make(chan parallelResult, 1)
				ordered <- resCh
				jobs <- parallelJob{buf: bp, n: n, nonce: nonce, result: resCh}
			} else {
				freeList <- bp
			}
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			if err != nil {
				outcomeCh <- dispatchOutcome{err: err}
				return
			}
		}
		var sum [crypto.HMACSize]byte
		copy(sum[:], h.Sum(nil))
		outcomeCh <- dispatchOutcome{mac: sum}
	}()

	// Drain in dispatch order. Buffers are always returned to freeList, even after a
	// send error, so the dispatcher never stalls waiting on freeList and the pipeline
	// can wind down cleanly instead of deadlocking.
	var sendErr error
	for resCh := range ordered {
		res := <-resCh
		if sendErr == nil {
			if err := send(res.block); err != nil {
				sendErr = err
				cancelOnce.Do(func() { close(cancel) })
			}
		}
		freeList <- res.buf
	}
	workerWG.Wait()
	outcome := <-outcomeCh

	if sendErr != nil {
		return [crypto.HMACSize]byte{}, sendErr
	}
	if outcome.err != nil {
		return [crypto.HMACSize]byte{}, outcome.err
	}
	return outcome.mac, nil
}
