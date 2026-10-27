// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package azblob

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"

	"github.com/iamvirul/sarc/storage/storagetest"
)

func TestFactoryRejectsMissingConfiguration(t *testing.T) {
	ctx := context.Background()
	if _, err := Factory(Options{Account: "acct"})(ctx, ""); err == nil {
		t.Error("empty container accepted")
	}
	if _, err := Factory(Options{})(ctx, "c"); err == nil {
		t.Error("missing account accepted")
	}
	if _, err := Factory(Options{Account: "acct", AccountKey: "not base64!"})(ctx, "c"); err == nil {
		t.Error("malformed shared key accepted")
	}
}

// testBackend returns a backend for SARC_TEST_AZURE_CONTAINER, created if missing, or
// skips. CI points it at Azurite through AZURE_STORAGE_CONNECTION_STRING.
func testBackend(t *testing.T) *Backend {
	t.Helper()
	name := os.Getenv("SARC_TEST_AZURE_CONTAINER")
	connStr := os.Getenv("AZURE_STORAGE_CONNECTION_STRING")
	if name == "" || connStr == "" {
		t.Skip("SARC_TEST_AZURE_CONTAINER or AZURE_STORAGE_CONNECTION_STRING not set")
	}
	b, err := Factory(Options{ConnectionString: connStr})(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	backend := b.(*Backend)
	if _, err := backend.container.Create(context.Background(), nil); err != nil && !bloberror.HasCode(err, bloberror.ContainerAlreadyExists) {
		t.Fatal(err)
	}
	return backend
}

func TestContract(t *testing.T) {
	b := testBackend(t)
	prefix := "sarc-test/" + strings.ReplaceAll(t.Name(), "/", "-") + "-" + time.Now().Format("150405.000000") + "/"
	storagetest.Run(t, b, prefix, storagetest.Options{LargeSize: 2*blockSize + 12345, Versioned: true})
}
