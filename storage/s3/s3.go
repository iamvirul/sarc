// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

// Package s3 is the storage backend for s3://bucket/key locations on Amazon S3 and
// S3-compatible stores (MinIO, Cloudflare R2, Backblaze B2, Wasabi, and others).
//
// Configuration comes from the AWS SDK's standard sources: AWS_REGION,
// AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, AWS_PROFILE and ~/.aws, SSO, and
// instance or pod roles. AWS_ENDPOINT_URL_S3 selects an S3-compatible endpoint.
package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/iamvirul/sarc/storage"
)

const (
	// MinPartSize is the smallest part S3 accepts, except for the last.
	MinPartSize = 5 << 20
	// DefaultPartSize is the size of the first multipart parts.
	DefaultPartSize = 16 << 20
	// maxPartSize caps part growth (see partSize).
	maxPartSize = 256 << 20
	// maxParts is S3's limit on parts per upload.
	maxParts = 10000
	// partGrowthInterval is how many parts are uploaded at each part size before it doubles.
	partGrowthInterval = 1000
	// uploadConcurrency is how many parts upload at once; memory is bounded by
	// (uploadConcurrency+1) parts.
	uploadConcurrency = 4
	// abortTimeout bounds the requests that start and discard an upload, which run
	// even after the writer's context ends.
	abortTimeout = 30 * time.Second
)

// Options configures the backend beyond the SDK's standard sources.
type Options struct {
	// UsePathStyle addresses buckets as endpoint/bucket rather than bucket.endpoint, as
	// some S3-compatible stores require.
	UsePathStyle bool
	// PartSize is the size of the first multipart parts; 0 means DefaultPartSize.
	PartSize int64
}

// Factory returns a storage.Factory for s3:// locations.
func Factory(opts Options) storage.Factory {
	return func(ctx context.Context, bucket string) (storage.Backend, error) {
		if bucket == "" {
			return nil, errors.New("s3:// location needs a bucket, as in s3://bucket/key")
		}
		if opts.PartSize == 0 {
			opts.PartSize = DefaultPartSize
		}
		if opts.PartSize < MinPartSize || opts.PartSize > maxPartSize {
			return nil, fmt.Errorf("part size must be between %d and %d bytes", MinPartSize, maxPartSize)
		}
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("load AWS configuration: %w", err)
		}
		if cfg.Region == "" {
			return nil, errors.New("no AWS region configured; set AWS_REGION or a profile region")
		}
		client := awss3.NewFromConfig(cfg, func(o *awss3.Options) { o.UsePathStyle = opts.UsePathStyle })
		return &Backend{
			client:   client,
			bucket:   bucket,
			partSize: opts.PartSize,
			checksum: checksumAlgorithm(cfg.RequestChecksumCalculation),
		}, nil
	}
}

// checksumAlgorithm returns the algorithm parts are checksummed with: CRC32, as the SDK
// uses for uploads, unless checksums are limited to operations requiring them.
func checksumAlgorithm(calc aws.RequestChecksumCalculation) types.ChecksumAlgorithm {
	if calc == aws.RequestChecksumCalculationWhenRequired {
		return ""
	}
	return types.ChecksumAlgorithmCrc32
}

// Backend serves one bucket.
type Backend struct {
	client   *awss3.Client
	bucket   string
	partSize int64
	checksum types.ChecksumAlgorithm
}

// Create returns a Writer that uploads key with a single PutObject when the object fits
// in one part, and as a multipart upload otherwise. A multipart upload stays invisible
// until Close completes it; Abort, or any failure, discards its parts.
func (b *Backend) Create(ctx context.Context, key string) (storage.Writer, error) {
	ctx, cancel := context.WithCancel(ctx)
	return &writer{
		ctx:    ctx,
		cancel: cancel,
		b:      b,
		key:    key,
		buf:    make([]byte, 0, b.partSize),
		slots:  make(chan struct{}, uploadConcurrency),
	}, nil
}

// partSize returns the size of part n (from 1): it doubles every partGrowthInterval
// parts up to maxPartSize, so the 10000-part limit allows archives of about 1.7 TiB
// from 16 MiB parts while small archives use small parts.
func partSize(first int64, n int) int64 {
	return min(first<<((n-1)/partGrowthInterval), maxPartSize)
}

type writer struct {
	ctx      context.Context
	cancel   context.CancelFunc
	b        *Backend
	key      string
	buf      []byte
	uploadID *string
	nextPart int
	slots    chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	parts    []types.CompletedPart
	err      error
	done     bool
}

func (w *writer) Write(p []byte) (int, error) {
	if w.done {
		return 0, errors.New("s3: write after Close or Abort")
	}
	written := 0
	for len(p) > 0 {
		if err := w.uploadErr(); err != nil {
			return written, err
		}
		limit := int(partSize(w.b.partSize, w.nextPart+1))
		n := min(len(p), limit-len(w.buf))
		w.buf = append(w.buf, p[:n]...)
		p, written = p[n:], written+n
		if len(w.buf) == limit {
			if err := w.flushPart(); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// flushPart starts uploading the buffered part in the background.
func (w *writer) flushPart() error {
	if w.uploadID == nil {
		// Not canceled with the writer: an upload created by a request whose response
		// was lost to cancellation could never be aborted, since its ID is unknown.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), abortTimeout)
		out, err := w.b.client.CreateMultipartUpload(ctx, &awss3.CreateMultipartUploadInput{
			Bucket: &w.b.bucket, Key: &w.key, ChecksumAlgorithm: w.b.checksum,
		})
		cancel()
		if err != nil {
			return wrapErr("start upload", err)
		}
		w.uploadID = out.UploadId
	}
	w.nextPart++
	if w.nextPart > maxParts {
		return fmt.Errorf("s3: archive exceeds %d parts", maxParts)
	}
	part, number := w.buf, int32(w.nextPart)
	w.buf = make([]byte, 0, partSize(w.b.partSize, w.nextPart+1))
	select {
	case w.slots <- struct{}{}:
	case <-w.ctx.Done():
		return w.ctx.Err()
	}
	w.wg.Add(1)
	go func() {
		defer func() { <-w.slots; w.wg.Done() }()
		out, err := w.b.client.UploadPart(w.ctx, &awss3.UploadPartInput{
			Bucket: &w.b.bucket, Key: &w.key, UploadId: w.uploadID, PartNumber: &number,
			Body: bytes.NewReader(part), ContentLength: aws.Int64(int64(len(part))),
			ChecksumAlgorithm: w.b.checksum,
		})
		w.mu.Lock()
		defer w.mu.Unlock()
		if err != nil {
			if w.err == nil {
				w.err = wrapErr(fmt.Sprintf("upload part %d", number), err)
			}
			w.cancel()
			return
		}
		w.parts = append(w.parts, types.CompletedPart{PartNumber: &number, ETag: out.ETag, ChecksumCRC32: out.ChecksumCRC32})
	}()
	return nil
}

func (w *writer) uploadErr() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

// Close uploads the rest and completes the object; on failure the upload is discarded.
func (w *writer) Close() error {
	if w.done {
		return nil
	}
	w.done = true
	defer w.cancel()
	if w.uploadID == nil {
		_, err := w.b.client.PutObject(w.ctx, &awss3.PutObjectInput{
			Bucket: &w.b.bucket, Key: &w.key, Body: bytes.NewReader(w.buf),
			ContentLength: aws.Int64(int64(len(w.buf))), ChecksumAlgorithm: w.b.checksum,
		})
		return wrapErr("put object", err)
	}
	var err error
	if len(w.buf) > 0 {
		err = w.flushPart()
	}
	w.wg.Wait()
	if err == nil {
		err = w.uploadErr()
	}
	if err == nil {
		sort.Slice(w.parts, func(i, j int) bool { return *w.parts[i].PartNumber < *w.parts[j].PartNumber })
		_, err = w.b.client.CompleteMultipartUpload(w.ctx, &awss3.CompleteMultipartUploadInput{
			Bucket: &w.b.bucket, Key: &w.key, UploadId: w.uploadID,
			MultipartUpload: &types.CompletedMultipartUpload{Parts: w.parts},
		})
		err = wrapErr("complete upload", err)
	}
	if err != nil {
		return errors.Join(err, w.abortUpload())
	}
	return nil
}

// Abort discards everything written.
func (w *writer) Abort() error {
	if w.done {
		return nil
	}
	w.done = true
	w.cancel()
	w.wg.Wait()
	return w.abortUpload()
}

// abortUpload discards the multipart upload, if one was started, with a fresh context
// since the writer's may have ended.
func (w *writer) abortUpload() error {
	if w.uploadID == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), abortTimeout)
	defer cancel()
	_, err := w.b.client.AbortMultipartUpload(ctx, &awss3.AbortMultipartUploadInput{
		Bucket: &w.b.bucket, Key: &w.key, UploadId: w.uploadID,
	})
	return wrapErr("abort upload", err)
}

// Open returns the current version of key, identified by its ETag.
func (b *Backend) Open(ctx context.Context, key string) (storage.Object, error) {
	out, err := b.client.HeadObject(ctx, &awss3.HeadObjectInput{Bucket: &b.bucket, Key: &key})
	if err != nil {
		return nil, wrapErr("open", err)
	}
	if out.ContentLength == nil || out.ETag == nil {
		return nil, errors.New("s3: open: response lacks size or ETag")
	}
	return &object{b: b, key: key, size: *out.ContentLength, etag: *out.ETag}, nil
}

type object struct {
	b    *Backend
	key  string
	size int64
	etag string
}

func (o *object) Size() int64 { return o.size }

// NewRangeReader reads a byte range of the version Open saw; If-Match makes a replaced
// object fail instead of mixing versions.
func (o *object) NewRangeReader(ctx context.Context, offset, length int64) (io.ReadCloser, error) {
	if length == 0 {
		return io.NopCloser(strings.NewReader("")), nil
	}
	rng := fmt.Sprintf("bytes=%d-", offset)
	if length > 0 {
		rng = fmt.Sprintf("bytes=%d-%d", offset, offset+length-1)
	}
	out, err := o.b.client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: &o.b.bucket, Key: &o.key, Range: &rng, IfMatch: &o.etag,
	})
	if err != nil {
		err = wrapErr("read", err)
		if errors.Is(err, storage.ErrNotFound) {
			err = fmt.Errorf("%w: %w", storage.ErrObjectChanged, err)
		}
		return nil, err
	}
	return out.Body, nil
}

// wrapErr adds context to err and maps missing objects and failed preconditions to
// storage.ErrNotFound and storage.ErrObjectChanged.
func wrapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NotFound", "NoSuchBucket":
			return fmt.Errorf("s3: %s: %w: %w", op, storage.ErrNotFound, err)
		case "PreconditionFailed":
			return fmt.Errorf("s3: %s: %w: %w", op, storage.ErrObjectChanged, err)
		}
	}
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.HTTPStatusCode() {
		case http.StatusNotFound:
			return fmt.Errorf("s3: %s: %w: %w", op, storage.ErrNotFound, err)
		case http.StatusPreconditionFailed:
			return fmt.Errorf("s3: %s: %w: %w", op, storage.ErrObjectChanged, err)
		}
	}
	return fmt.Errorf("s3: %s: %w", op, err)
}
