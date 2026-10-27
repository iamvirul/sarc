// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// SDKs retry a request that fails to start, but not a response body that breaks off
// partway, which is likely over a long download. The readers here reopen the object at
// the current offset instead.
const (
	// maxConsecutiveResumes bounds reopen attempts without progress in between.
	maxConsecutiveResumes = 5
	resumeBaseDelay       = 200 * time.Millisecond
	resumeMaxDelay        = 5 * time.Second
)

// rangeReader reads [off, end) of an object, opening it on first read and reopening
// it at the current offset when a read fails.
type rangeReader struct {
	ctx     context.Context
	obj     Object
	off     int64
	end     int64
	body    io.ReadCloser
	resumes int
	sleep   func(context.Context, time.Duration) error
}

func newRangeReader(ctx context.Context, obj Object, off, end int64) *rangeReader {
	return &rangeReader{ctx: ctx, obj: obj, off: off, end: end, sleep: sleepContext}
}

func (r *rangeReader) Read(p []byte) (int, error) {
	if r.off >= r.end {
		return 0, io.EOF
	}
	if int64(len(p)) > r.end-r.off {
		p = p[:r.end-r.off]
	}
	for {
		if r.body == nil {
			body, err := r.obj.NewRangeReader(r.ctx, r.off, r.end-r.off)
			if err != nil {
				if retryErr := r.backoff(err); retryErr != nil {
					return 0, retryErr
				}
				continue
			}
			r.body = body
		}
		n, err := r.body.Read(p)
		r.off += int64(n)
		if n > 0 {
			r.resumes = 0
		}
		if err == nil || (err == io.EOF && r.off >= r.end) {
			return n, nil
		}
		// The body failed, or ended before the range did.
		r.body.Close()
		r.body = nil
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		if n > 0 {
			return n, nil
		}
		if retryErr := r.backoff(err); retryErr != nil {
			return 0, retryErr
		}
	}
}

// backoff waits before reopening after err, or returns err when it is permanent or the
// attempts are used up.
func (r *rangeReader) backoff(err error) error {
	if r.ctx.Err() != nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrObjectChanged) {
		return err
	}
	if r.resumes >= maxConsecutiveResumes {
		return fmt.Errorf("storage: read at offset %d failed after %d attempts: %w", r.off, r.resumes+1, err)
	}
	delay := min(resumeBaseDelay<<r.resumes, resumeMaxDelay)
	r.resumes++
	if serr := r.sleep(r.ctx, delay); serr != nil {
		return err
	}
	return nil
}

func (r *rangeReader) Close() error {
	if r.body == nil {
		return nil
	}
	err := r.body.Close()
	r.body = nil
	return err
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// NewReader returns a sequential reader of obj from its start. It opens the object on
// the first read, as one streaming request, and reopens it at the current offset when
// the connection breaks.
func NewReader(ctx context.Context, obj Object) io.ReadCloser {
	return newRangeReader(ctx, obj, 0, obj.Size())
}

// NewReaderAt returns an io.ReaderAt over obj that issues one range request per call,
// safe for concurrent use.
func NewReaderAt(ctx context.Context, obj Object) io.ReaderAt {
	return readerAt{ctx: ctx, obj: obj}
}

type readerAt struct {
	ctx context.Context
	obj Object
}

func (ra readerAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("storage: negative offset %d", off)
	}
	size := ra.obj.Size()
	if off >= size {
		return 0, io.EOF
	}
	want := min(int64(len(p)), size-off)
	r := newRangeReader(ra.ctx, ra.obj, off, off+want)
	defer r.Close()
	n, err := io.ReadFull(r, p[:want])
	if err != nil {
		return n, err
	}
	if want < int64(len(p)) {
		return n, io.EOF
	}
	return n, nil
}
