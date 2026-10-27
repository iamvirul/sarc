// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package gcs

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/googleapi"

	"github.com/iamvirul/sarc/storage/storagetest"
)

func TestNewRejectsEmptyBucket(t *testing.T) {
	if _, err := New(context.Background(), ""); err == nil {
		t.Fatal("empty bucket accepted")
	}
}

// testBackend returns a backend for SARC_TEST_GCS_BUCKET, created if missing, or
// skips. CI points it at fake-gcs-server through STORAGE_EMULATOR_HOST.
func testBackend(t *testing.T) *Backend {
	t.Helper()
	bucket := os.Getenv("SARC_TEST_GCS_BUCKET")
	if bucket == "" {
		t.Skip("SARC_TEST_GCS_BUCKET not set")
	}
	b, err := New(context.Background(), bucket)
	if err != nil {
		t.Fatal(err)
	}
	backend := b.(*Backend)
	err = backend.bucket.Create(context.Background(), "sarc-test", nil)
	var apiErr *googleapi.Error
	if err != nil && !(errors.As(err, &apiErr) && apiErr.Code == http.StatusConflict) {
		t.Fatal(err)
	}
	return backend
}

func TestContract(t *testing.T) {
	b := testBackend(t)
	prefix := "sarc-test/" + strings.ReplaceAll(t.Name(), "/", "-") + "-" + time.Now().Format("150405.000000") + "/"
	storagetest.Run(t, b, prefix, storagetest.Options{LargeSize: chunkSize + chunkSize/2, Versioned: true})
}
