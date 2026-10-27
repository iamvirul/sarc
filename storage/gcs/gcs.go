// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

// Package gcs is the storage backend for gs://bucket/object locations on Google Cloud
// Storage. Credentials come from Application Default Credentials
// (GOOGLE_APPLICATION_CREDENTIALS, gcloud, or the metadata server);
// STORAGE_EMULATOR_HOST selects an emulator.
package gcs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	gcstorage "cloud.google.com/go/storage"

	"github.com/iamvirul/sarc/storage"
)

// chunkSize is the resumable upload chunk, buffered in memory.
const chunkSize = 16 << 20

// New returns the backend for a gs:// bucket.
func New(ctx context.Context, bucket string) (storage.Backend, error) {
	if bucket == "" {
		return nil, errors.New("gs:// location needs a bucket, as in gs://bucket/object")
	}
	// JSON API reads honor generation-pinned range reads on emulators as well as on GCS.
	client, err := gcstorage.NewClient(ctx, gcstorage.WithJSONReads())
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	return &Backend{bucket: client.Bucket(bucket)}, nil
}

// Backend serves one bucket.
type Backend struct {
	bucket *gcstorage.BucketHandle
}

// Create returns a Writer for a resumable upload, which creates the object only when
// Close finalizes it.
func (b *Backend) Create(ctx context.Context, key string) (storage.Writer, error) {
	ctx, cancel := context.WithCancel(ctx)
	w := b.bucket.Object(key).NewWriter(ctx)
	w.ChunkSize = chunkSize
	return &writer{w: w, cancel: cancel}, nil
}

type writer struct {
	w      *gcstorage.Writer
	cancel context.CancelFunc
	done   bool
}

func (w *writer) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	return n, wrapErr("write", err)
}

func (w *writer) Close() error {
	if w.done {
		return nil
	}
	w.done = true
	defer w.cancel()
	return wrapErr("finalize upload", w.w.Close())
}

// Abort cancels the upload; the library then never finalizes the object.
func (w *writer) Abort() error {
	if w.done {
		return nil
	}
	w.done = true
	w.cancel()
	// Close reports the cancellation itself; it is only called to release the upload.
	_ = w.w.Close()
	return nil
}

// Open returns the current generation of key.
func (b *Backend) Open(ctx context.Context, key string) (storage.Object, error) {
	h := b.bucket.Object(key)
	attrs, err := h.Attrs(ctx)
	if err != nil {
		return nil, wrapErr("open", err)
	}
	return &object{h: h.Generation(attrs.Generation), size: attrs.Size}, nil
}

type object struct {
	h    *gcstorage.ObjectHandle // pinned to one generation
	size int64
}

func (o *object) Size() int64 { return o.size }

// NewRangeReader reads a byte range of the generation Open saw. Once the object is
// replaced that generation is gone (without bucket versioning), which is reported as
// storage.ErrObjectChanged.
func (o *object) NewRangeReader(ctx context.Context, offset, length int64) (io.ReadCloser, error) {
	if length == 0 {
		return io.NopCloser(strings.NewReader("")), nil
	}
	r, err := o.h.NewRangeReader(ctx, offset, length)
	if err != nil {
		err = wrapErr("read", err)
		if errors.Is(err, storage.ErrNotFound) {
			err = fmt.Errorf("%w: %w", storage.ErrObjectChanged, err)
		}
		return nil, err
	}
	return r, nil
}

// wrapErr adds context to err and maps missing objects and buckets to
// storage.ErrNotFound.
func wrapErr(op string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, gcstorage.ErrObjectNotExist), errors.Is(err, gcstorage.ErrBucketNotExist):
		return fmt.Errorf("gcs: %s: %w: %w", op, storage.ErrNotFound, err)
	}
	return fmt.Errorf("gcs: %s: %w", op, err)
}
