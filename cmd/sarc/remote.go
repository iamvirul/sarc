// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/iamvirul/sarc/storage"
	"github.com/iamvirul/sarc/storage/azblob"
	"github.com/iamvirul/sarc/storage/gcs"
	"github.com/iamvirul/sarc/storage/local"
	"github.com/iamvirul/sarc/storage/s3"
)

// Environment variables configuring storage backends beyond their SDKs' own.
const (
	envS3PathStyle     = "SARC_S3_PATH_STYLE"
	envAzureConnection = "AZURE_STORAGE_CONNECTION_STRING"
	envAzureAccount    = "AZURE_STORAGE_ACCOUNT"
	envAzureAccountKey = "AZURE_STORAGE_KEY"
)

// remoteSchemesHelp lists the URL forms in flag help.
const remoteSchemesHelp = "s3://bucket/key, gs://bucket/key, azblob://container/blob, or file:///path"

// storageRegistry returns the backends for archive URLs, configured from the
// environment.
func storageRegistry() (*storage.Registry, error) {
	pathStyle := false
	if v := os.Getenv(envS3PathStyle); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("%s must be true or false, got %q", envS3PathStyle, v)
		}
		pathStyle = b
	}
	r := storage.NewRegistry()
	for scheme, f := range map[string]storage.Factory{
		"file": local.New,
		"s3":   s3.Factory(s3.Options{UsePathStyle: pathStyle}),
		"gs":   gcs.New,
		"azblob": azblob.Factory(azblob.Options{
			ConnectionString: os.Getenv(envAzureConnection),
			Account:          os.Getenv(envAzureAccount),
			AccountKey:       os.Getenv(envAzureAccountKey),
		}),
	} {
		if err := r.Register(scheme, f); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// remoteLocation parses path as a storage URL, reporting false for a local path or "-".
func remoteLocation(path string) (storage.Location, bool, error) {
	if path == stdioPath {
		return storage.Location{}, false, nil
	}
	return storage.ParseLocation(path)
}

// isRemote reports whether path names a storage URL rather than a local file.
func isRemote(path string) bool {
	_, ok, _ := remoteLocation(path)
	return ok
}

// openBackend returns the backend serving loc.
func openBackend(ctx context.Context, loc storage.Location) (storage.Backend, error) {
	registry, err := storageRegistry()
	if err != nil {
		return nil, err
	}
	return registry.Backend(ctx, loc)
}

// commandContext returns cmd's context, or the background context for a command run
// outside Execute.
func commandContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

// interruptContext returns a context canceled by the first interrupt or SIGTERM, so an
// upload in progress is aborted instead of left incomplete. Default signal handling is
// restored once the context ends, so a second signal exits at once.
func interruptContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop()
	}()
	return ctx, stop
}
