// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bufio"
	stdhmac "crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"os"

	"github.com/iamvirul/sarc/crypto"
)

// verifiedFileBufferSize batches plaintext writes to the temporary file.
const verifiedFileBufferSize = 1 << 20

// tempFilePattern names in-progress extractions: hidden, and recognisable if a crash
// leaves one behind.
const tempFilePattern = ".sarc-extract-*"

// verifiedFile accumulates one entry's plaintext in a temporary file beside its final
// destination while computing the plaintext HMAC. It becomes visible under its real
// name only through publish, after verify succeeds.
type verifiedFile struct {
	f         *os.File
	w         *bufio.Writer
	mac       hash.Hash
	size      int64
	published bool
}

// newVerifiedFile creates the temporary file in dir (mode 0600) keyed for HMAC by fileKey.
func newVerifiedFile(dir string, fileKey [crypto.KeySize]byte) (*verifiedFile, error) {
	f, err := os.CreateTemp(dir, tempFilePattern)
	if err != nil {
		return nil, err
	}
	return &verifiedFile{
		f:   f,
		w:   bufio.NewWriterSize(f, verifiedFileBufferSize),
		mac: stdhmac.New(sha256.New, fileKey[:]),
	}, nil
}

// write appends plaintext and folds it into the running HMAC. It is a blockSink.
func (v *verifiedFile) write(plaintext []byte) error {
	v.mac.Write(plaintext)
	v.size += int64(len(plaintext))
	_, err := v.w.Write(plaintext)
	return err
}

// verify checks the running HMAC (in constant time) and size against the trailer.
func (v *verifiedFile) verify(trailer trailerInfo) error {
	if !stdhmac.Equal(v.mac.Sum(nil), trailer.hmac[:]) {
		return recoverable(ErrCodeIntegrityFail, "plaintext HMAC mismatch", nil)
	}
	if trailer.hasSize && trailer.plaintextSize != uint64(v.size) {
		return recoverable(ErrCodeIntegrityFail, "plaintext size mismatch", nil)
	}
	return nil
}

// publish flushes, applies perm, and atomically renames the file to path, replacing any
// existing file there.
func (v *verifiedFile) publish(path string, perm os.FileMode) error {
	if err := v.w.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	if err := v.f.Chmod(perm); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if err := v.f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(v.f.Name(), path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	v.published = true
	return nil
}

// discard closes and removes the temporary file unless it was published. Safe to call
// more than once and after publish. It runs only on paths already returning an error, so
// close and remove failures are deliberately not reported over that error.
func (v *verifiedFile) discard() {
	if v.published {
		return
	}
	_ = v.f.Close()
	_ = os.Remove(v.f.Name())
}
