// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package s3

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/iamvirul/sarc/storage/storagetest"
)

func TestPartSizeGrowsAndCaps(t *testing.T) {
	cases := map[int]int64{1: 16 << 20, 1000: 16 << 20, 1001: 32 << 20, 3001: 128 << 20, 4001: 256 << 20, 10000: 256 << 20}
	for n, want := range cases {
		if got := partSize(DefaultPartSize, n); got != want {
			t.Errorf("partSize(%d) = %d, want %d", n, got, want)
		}
	}
	var total int64
	for n := 1; n <= maxParts; n++ {
		total += partSize(DefaultPartSize, n)
	}
	if total < 1700<<30 {
		t.Fatalf("10000 parts hold only %d bytes", total)
	}
}

func TestFactoryRejectsBadOptions(t *testing.T) {
	ctx := context.Background()
	if _, err := Factory(Options{})(ctx, ""); err == nil {
		t.Error("empty bucket accepted")
	}
	if _, err := Factory(Options{PartSize: MinPartSize - 1})(ctx, "b"); err == nil {
		t.Error("part size below the S3 minimum accepted")
	}
}

// testBackend returns a backend for SARC_TEST_S3_BUCKET, created if missing, or skips.
// CI points it at MinIO through AWS_ENDPOINT_URL_S3 and SARC_TEST_S3_PATH_STYLE.
func testBackend(t *testing.T) *Backend {
	t.Helper()
	bucket := os.Getenv("SARC_TEST_S3_BUCKET")
	if bucket == "" {
		t.Skip("SARC_TEST_S3_BUCKET not set")
	}
	b, err := Factory(Options{PartSize: MinPartSize, UsePathStyle: os.Getenv("SARC_TEST_S3_PATH_STYLE") != ""})(context.Background(), bucket)
	if err != nil {
		t.Fatal(err)
	}
	backend := b.(*Backend)
	_, err = backend.client.CreateBucket(context.Background(), &awss3.CreateBucketInput{Bucket: &bucket})
	var owned *types.BucketAlreadyOwnedByYou
	var exists *types.BucketAlreadyExists
	if err != nil && !errors.As(err, &owned) && !errors.As(err, &exists) {
		t.Fatal(err)
	}
	return backend
}

func testPrefix(t *testing.T) string {
	return "sarc-test/" + strings.ReplaceAll(t.Name(), "/", "-") + "-" + time.Now().Format("150405.000000") + "/"
}

func TestContract(t *testing.T) {
	b := testBackend(t)
	storagetest.Run(t, b, testPrefix(t), storagetest.Options{LargeSize: 3*MinPartSize + 12345, Versioned: true})
}

func TestAbortDiscardsMultipartUpload(t *testing.T) {
	b := testBackend(t)
	key := testPrefix(t) + "aborted.sarc"
	w, err := b.Create(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 2*MinPartSize+1)); err != nil {
		t.Fatal(err)
	}
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}
	out, err := b.client.ListMultipartUploads(context.Background(), &awss3.ListMultipartUploadsInput{Bucket: &b.bucket, Prefix: &key})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Uploads) != 0 {
		t.Fatalf("%d multipart uploads left after Abort", len(out.Uploads))
	}
}
