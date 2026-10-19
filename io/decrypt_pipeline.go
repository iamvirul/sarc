// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"sync"

	"github.com/iamvirul/sarc/crypto"
)

// decryptPipelineDepth is the number of in-flight blocks buffered per worker on the
// decrypt side, mirroring parallelPipelineDepth on the encrypt side.
const decryptPipelineDepth = 4

// blockOpener authenticates, decrypts, and decodes one data block. Implementations
// must be safe for concurrent use. *crypto.EncryptionManager satisfies it.
type blockOpener interface {
	DecryptBlock(block crypto.EncryptedBlock) ([]byte, error)
}

// blockReader supplies one (nonce, ciphertext) pair per call. ok is false once the
// data-block sentinel is reached; err is set on a truncated or malformed stream.
type blockReader func() (nonce [crypto.NonceSize]byte, ciphertext []byte, ok bool, err error)

type decryptJob struct {
	nonce  [crypto.NonceSize]byte
	ct     []byte
	result chan decryptResult
}

type decryptResult struct {
	pt  []byte
	err error
}

// blockSink receives each decrypted block's plaintext in stream order. The slice is
// only valid for the duration of the call.
type blockSink func(plaintext []byte) error

// sinkError wraps an error returned by a blockSink, so callers can tell output failures
// (for example a full disk) apart from authentication failures.
type sinkError struct{ err error }

func (e *sinkError) Error() string { return e.err.Error() }
func (e *sinkError) Unwrap() error { return e.err }

// decryptBlocksParallel authenticates and decrypts a file's data blocks, handing each
// plaintext block to sink in original order. next is called sequentially by an internal
// dispatcher goroutine (block framing is a variable-length stream, so it must be parsed
// in order); the CPU-bound AES-256-GCM Open call for each block is handed off to one of
// `workers` goroutines sharing em, which is safe for concurrent decrypt calls. At most
// workers*decryptPipelineDepth blocks are in flight, so memory is bounded regardless of
// file size.
//
// After a decrypt or sink failure it stops calling sink but keeps consuming blocks
// through the sentinel, so the caller's stream stays aligned on the next field.
// Falls back to sequential decryption when workers < 2.
func decryptBlocksParallel(em blockOpener, workers int, next blockReader, sink blockSink) error {
	if workers < 2 {
		return decryptBlocksSequential(em, next, sink)
	}

	jobs := make(chan decryptJob, workers*decryptPipelineDepth)
	ordered := make(chan chan decryptResult, workers*decryptPipelineDepth)

	var workerWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for j := range jobs {
				pt, err := em.DecryptBlock(crypto.EncryptedBlock{Nonce: j.nonce, Ciphertext: j.ct})
				j.result <- decryptResult{pt: pt, err: err}
			}
		}()
	}

	readErrCh := make(chan error, 1)
	go func() {
		defer close(jobs)
		defer close(ordered)
		for {
			nonce, ct, ok, err := next()
			if err != nil {
				readErrCh <- err
				return
			}
			if !ok {
				break
			}
			resCh := make(chan decryptResult, 1)
			ordered <- resCh
			jobs <- decryptJob{nonce: nonce, ct: ct, result: resCh}
		}
		readErrCh <- nil
	}()

	var firstErr error
	for resCh := range ordered {
		res := <-resCh
		if firstErr != nil {
			continue
		}
		if res.err != nil {
			firstErr = res.err
			continue
		}
		if err := sink(res.pt); err != nil {
			firstErr = &sinkError{err: err}
		}
	}
	workerWG.Wait()

	if firstErr != nil {
		return firstErr
	}
	return <-readErrCh
}

// decryptBlocksSequential decrypts blocks one at a time on the calling goroutine, with
// the same ordering, failure, and draining behaviour as decryptBlocksParallel.
func decryptBlocksSequential(em blockOpener, next blockReader, sink blockSink) error {
	var firstErr error
	for {
		nonce, ct, ok, err := next()
		if err != nil {
			return err
		}
		if !ok {
			return firstErr
		}
		if firstErr != nil {
			continue
		}
		pt, err := em.DecryptBlock(crypto.EncryptedBlock{Nonce: nonce, Ciphertext: ct})
		if err != nil {
			firstErr = err
			continue
		}
		if err := sink(pt); err != nil {
			firstErr = &sinkError{err: err}
		}
	}
}
