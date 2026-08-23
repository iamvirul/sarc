// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"sync"

	"github.com/iamvirul/sarc/crypto"
)

// decryptPipelineDepth is the number of in-flight blocks buffered per worker on the
// decrypt side, mirroring parallelPipelineDepth on the encrypt side.
const decryptPipelineDepth = 4

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

// decryptBlocksParallel authenticates and decrypts a file's data blocks, preserving
// their original order in the returned plaintext. next is called sequentially by an
// internal dispatcher goroutine (block framing is a variable-length stream, so it must
// be parsed in order); the CPU-bound AES-256-GCM Open call for each block is handed off
// to one of `workers` goroutines sharing em, which is safe for concurrent decrypt calls.
//
// Falls back to sequential decryption when workers < 2.
func decryptBlocksParallel(em *crypto.EncryptionManager, workers int, next blockReader) ([]byte, error) {
	if workers < 2 {
		return decryptBlocksSequential(em, next)
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

	var out bytes.Buffer
	var decryptErr error
	for resCh := range ordered {
		res := <-resCh
		if decryptErr == nil && res.err != nil {
			decryptErr = res.err
		}
		if decryptErr == nil {
			out.Write(res.pt)
		}
	}
	workerWG.Wait()

	if decryptErr != nil {
		return nil, decryptErr
	}
	if err := <-readErrCh; err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// decryptBlocksSequential decrypts blocks one at a time on the calling goroutine.
func decryptBlocksSequential(em *crypto.EncryptionManager, next blockReader) ([]byte, error) {
	var out bytes.Buffer
	for {
		nonce, ct, ok, err := next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		pt, err := em.DecryptBlock(crypto.EncryptedBlock{Nonce: nonce, Ciphertext: ct})
		if err != nil {
			return nil, err
		}
		out.Write(pt)
	}
	return out.Bytes(), nil
}
