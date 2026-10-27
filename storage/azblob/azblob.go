// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

// Package azblob is the storage backend for azblob://container/blob locations on Azure
// Blob Storage, as block blobs.
package azblob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	sdk "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"

	"github.com/iamvirul/sarc/storage"
)

const (
	// blockSize is the upload block size; 50000 blocks allow blobs of about 780 GiB.
	blockSize = 16 << 20
	// uploadConcurrency is how many blocks upload at once, each buffered in memory.
	uploadConcurrency = 4
)

// Options selects the account and credential. ConnectionString, when set, carries both
// (and an endpoint, as for the Azurite emulator); otherwise Account names the account
// and AccountKey, when set, is its shared key, or else the default Azure credential
// chain (environment, workload or managed identity, Azure CLI) is used.
type Options struct {
	ConnectionString string
	Account          string
	AccountKey       string
}

// Factory returns a storage.Factory for azblob:// locations.
func Factory(opts Options) storage.Factory {
	return func(_ context.Context, containerName string) (storage.Backend, error) {
		if containerName == "" {
			return nil, errors.New("azblob:// location needs a container, as in azblob://container/blob")
		}
		client, err := newClient(opts)
		if err != nil {
			return nil, err
		}
		return &Backend{container: client.ServiceClient().NewContainerClient(containerName)}, nil
	}
}

func newClient(opts Options) (*sdk.Client, error) {
	if opts.ConnectionString != "" {
		return sdk.NewClientFromConnectionString(opts.ConnectionString, nil)
	}
	if opts.Account == "" {
		return nil, errors.New("no Azure storage account configured; set AZURE_STORAGE_ACCOUNT or AZURE_STORAGE_CONNECTION_STRING")
	}
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", opts.Account)
	if opts.AccountKey != "" {
		cred, err := sdk.NewSharedKeyCredential(opts.Account, opts.AccountKey)
		if err != nil {
			return nil, fmt.Errorf("shared key: %w", err)
		}
		return sdk.NewClientWithSharedKeyCredential(serviceURL, cred, nil)
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("default Azure credential: %w", err)
	}
	return sdk.NewClient(serviceURL, cred, nil)
}

// Backend serves one container.
type Backend struct {
	container *container.Client
}

// Create returns a Writer that uploads blocks as they fill and commits the block list
// only on Close, so the blob is not created or replaced until then; uncommitted blocks
// of an aborted upload are discarded by the service.
func (b *Backend) Create(ctx context.Context, key string) (storage.Writer, error) {
	pr, pw := io.Pipe()
	w := &writer{pw: pw, result: make(chan error, 1)}
	bb := b.container.NewBlockBlobClient(key)
	go func() {
		_, err := bb.UploadStream(ctx, pr, &blockblob.UploadStreamOptions{BlockSize: blockSize, Concurrency: uploadConcurrency})
		pr.CloseWithError(err)
		w.result <- wrapErr("upload", err)
	}()
	return w, nil
}

// errAborted stops an upload whose writer was aborted.
var errAborted = errors.New("azblob: upload aborted")

type writer struct {
	pw     *io.PipeWriter
	result chan error
	done   bool
}

func (w *writer) Write(p []byte) (int, error) {
	n, err := w.pw.Write(p)
	if err != nil {
		return n, fmt.Errorf("azblob: write: %w", err)
	}
	return n, nil
}

func (w *writer) Close() error {
	if w.done {
		return nil
	}
	w.done = true
	w.pw.Close()
	return <-w.result
}

func (w *writer) Abort() error {
	if w.done {
		return nil
	}
	w.done = true
	w.pw.CloseWithError(errAborted)
	if err := <-w.result; err != nil && !errors.Is(err, errAborted) {
		return err
	}
	return nil
}

// Open returns the current version of key, identified by its ETag.
func (b *Backend) Open(ctx context.Context, key string) (storage.Object, error) {
	bb := b.container.NewBlockBlobClient(key)
	props, err := bb.GetProperties(ctx, nil)
	if err != nil {
		return nil, wrapErr("open", err)
	}
	if props.ContentLength == nil || props.ETag == nil {
		return nil, errors.New("azblob: open: response lacks size or ETag")
	}
	return &object{bb: bb, size: *props.ContentLength, etag: *props.ETag}, nil
}

type object struct {
	bb   *blockblob.Client
	size int64
	etag azcore.ETag
}

func (o *object) Size() int64 { return o.size }

// NewRangeReader reads a byte range of the version Open saw; If-Match makes a replaced
// blob fail instead of mixing versions.
func (o *object) NewRangeReader(ctx context.Context, offset, length int64) (io.ReadCloser, error) {
	if length == 0 {
		return io.NopCloser(strings.NewReader("")), nil
	}
	rng := blob.HTTPRange{Offset: offset}
	if length > 0 {
		rng.Count = length
	}
	resp, err := o.bb.DownloadStream(ctx, &blob.DownloadStreamOptions{
		Range: rng,
		AccessConditions: &blob.AccessConditions{
			ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfMatch: &o.etag},
		},
	})
	if err != nil {
		err = wrapErr("read", err)
		if errors.Is(err, storage.ErrNotFound) {
			err = fmt.Errorf("%w: %w", storage.ErrObjectChanged, err)
		}
		return nil, err
	}
	return resp.Body, nil
}

// wrapErr adds context to err and maps missing blobs and failed preconditions to
// storage.ErrNotFound and storage.ErrObjectChanged.
func wrapErr(op string, err error) error {
	switch {
	case err == nil:
		return nil
	case bloberror.HasCode(err, bloberror.BlobNotFound, bloberror.ContainerNotFound):
		return fmt.Errorf("azblob: %s: %w: %w", op, storage.ErrNotFound, err)
	case bloberror.HasCode(err, bloberror.ConditionNotMet):
		return fmt.Errorf("azblob: %s: %w: %w", op, storage.ErrObjectChanged, err)
	}
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) && respErr.StatusCode == 404 {
		return fmt.Errorf("azblob: %s: %w: %w", op, storage.ErrNotFound, err)
	}
	return fmt.Errorf("azblob: %s: %w", op, err)
}
