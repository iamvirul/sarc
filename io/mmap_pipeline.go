// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	stdhmac "crypto/hmac"
	"crypto/sha256"
	"errors"
	"os"
	"sync"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// mmapThreshold is the smallest file size for which memory-mapping is attempted.
// Below this, the mmap/munmap syscall overhead and page-fault cost outweigh the
// benefit of avoiding the buffered-reader copy.
const mmapThreshold = 64 * 1024 * 1024

// tryMmap memory-maps f read-only when size is at least mmapThreshold, returning an
// error otherwise (including on unsupported platforms or a failed mmap syscall) so the
// caller can fall back to the buffered reader path. That fallback is always correct;
// mmap is purely an I/O-path optimisation with no effect on the archive's wire format.
func tryMmap(f *os.File, size int64) (*mmappedFile, error) {
	if size < mmapThreshold {
		return nil, errors.New("io/mmap: file below mmap threshold")
	}
	return newMmappedFile(f, size)
}

type mmapJob struct {
	plaintext []byte // slice of the mmapped file; never copied
	nonce     [crypto.NonceSize]byte
	buf       *[]byte // pooled ciphertext-only destination buffer
	result    chan parallelResult
}

// encryptAndStreamMmap is a variant of encryptAndStreamParallel that sources plaintext
// directly from a memory-mapped file (data) instead of an io.Reader. Each chunk is a
// slice of data itself, so reading it is a direct touch of OS-managed page-cache pages
// with no intermediate copy into a userspace read buffer; the pooled buffers here hold
// only AES-256-GCM ciphertext output. Falls back to sequential encryption on one
// goroutine when workers < 2.
func encryptAndStreamMmap(
	data []byte,
	fb *archive.FrameBuilder,
	hmacKey [crypto.KeySize]byte,
	workers int,
	progress ProgressTracker,
	send func(archive.DataBlock) error,
) ([crypto.HMACSize]byte, error) {
	if workers < 2 {
		return encryptMmapSequential(data, fb, hmacKey, progress, send)
	}

	bufCount := workers * parallelPipelineDepth
	freeList := make(chan *[]byte, bufCount)
	for i := 0; i < bufCount; i++ {
		b := make([]byte, bufSize)
		freeList <- &b
	}

	jobs := make(chan mmapJob, bufCount)
	ordered := make(chan chan parallelResult, bufCount)
	cancel := make(chan struct{})
	var cancelOnce sync.Once

	var workerWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for j := range jobs {
				block := fb.EncryptChunkWithNonceInto(j.nonce, j.plaintext, (*j.buf)[:0])
				j.result <- parallelResult{block: block, buf: j.buf}
			}
		}()
	}

	outcomeCh := make(chan dispatchOutcome, 1)
	go func() {
		defer close(jobs)
		defer close(ordered)
		h := stdhmac.New(sha256.New, hmacKey[:])
		offset := 0
		for offset < len(data) {
			select {
			case <-cancel:
				outcomeCh <- dispatchOutcome{err: errDispatchCanceled}
				return
			default:
			}

			size := fb.NextChunkSize()
			if size > len(data)-offset {
				size = len(data) - offset
			}
			chunk := data[offset : offset+size]
			offset += size

			h.Write(chunk)
			progress.BytesProcessed(int64(size))

			nonce, nerr := fb.NextNonce()
			if nerr != nil {
				outcomeCh <- dispatchOutcome{err: nerr}
				return
			}

			bp := <-freeList
			resCh := make(chan parallelResult, 1)
			ordered <- resCh
			jobs <- mmapJob{plaintext: chunk, nonce: nonce, buf: bp, result: resCh}
		}
		var sum [crypto.HMACSize]byte
		copy(sum[:], h.Sum(nil))
		outcomeCh <- dispatchOutcome{mac: sum}
	}()

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

// encryptMmapSequential encrypts a memory-mapped file's chunks on the calling
// goroutine, reusing a single ciphertext buffer across chunks.
func encryptMmapSequential(
	data []byte,
	fb *archive.FrameBuilder,
	hmacKey [crypto.KeySize]byte,
	progress ProgressTracker,
	send func(archive.DataBlock) error,
) ([crypto.HMACSize]byte, error) {
	h := stdhmac.New(sha256.New, hmacKey[:])
	buf := make([]byte, 0, bufSize)

	offset := 0
	for offset < len(data) {
		size := fb.NextChunkSize()
		if size > len(data)-offset {
			size = len(data) - offset
		}
		chunk := data[offset : offset+size]
		offset += size

		h.Write(chunk)
		progress.BytesProcessed(int64(size))

		nonce, err := fb.NextNonce()
		if err != nil {
			return [crypto.HMACSize]byte{}, err
		}
		block := fb.EncryptChunkWithNonceInto(nonce, chunk, buf[:0])
		if err := send(block); err != nil {
			return [crypto.HMACSize]byte{}, err
		}
	}

	var sum [crypto.HMACSize]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}
