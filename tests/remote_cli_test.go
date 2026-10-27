// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const remotePassword = "remote-cli-password"

// remoteBases returns the storage URL prefixes to test: a file:// directory always, and
// each cloud emulator configured for the storage backend tests (see their testBackend),
// whose buckets those tests create.
func remoteBases(t *testing.T) map[string]string {
	t.Helper()
	run := strings.ReplaceAll(t.Name(), "/", "-") + "-" + time.Now().Format("150405.000000")
	bases := map[string]string{"file": "file://" + filepath.ToSlash(withRootSlash(t.TempDir())) + "/"}
	if b := os.Getenv("SARC_TEST_S3_BUCKET"); b != "" {
		bases["s3"] = "s3://" + b + "/sarc-cli/" + run + "/"
	}
	if b := os.Getenv("SARC_TEST_GCS_BUCKET"); b != "" {
		bases["gs"] = "gs://" + b + "/sarc-cli/" + run + "/"
	}
	if b := os.Getenv("SARC_TEST_AZURE_CONTAINER"); b != "" && os.Getenv("AZURE_STORAGE_CONNECTION_STRING") != "" {
		bases["azblob"] = "azblob://" + b + "/sarc-cli/" + run + "/"
	}
	return bases
}

func withRootSlash(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

// remoteTree writes a small tree with a file spanning several data blocks.
func remoteTree(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "data")
	big := make([]byte, 2<<20+77)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"big.bin":       big,
		"notes.txt":     bytes.Repeat([]byte("remote archive\n"), 500),
		"sub/small.cfg": []byte("k=v"),
	}
	for name, data := range files {
		p := filepath.Join(src, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return src, files
}

func requireTree(t *testing.T, root string, want map[string][]byte) {
	t.Helper()
	for name, data := range want {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("%s: content differs after extraction", name)
		}
	}
}

func mustRunSarc(t *testing.T, args ...string) string {
	t.Helper()
	out, err := runSarc(t, nil, args...)
	if err != nil {
		t.Fatalf("sarc %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// TestRemoteCLIRoundtrip archives to, lists, verifies, and extracts from each storage
// backend through the real binary.
func TestRemoteCLIRoundtrip(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the sarc binary")
	}
	src, files := remoteTree(t)
	for scheme, base := range remoteBases(t) {
		t.Run(scheme, func(t *testing.T) {
			url := base + "backup.sarc"
			mustRunSarc(t, "archive", "-p", remotePassword, "-o", url, src)

			listing := mustRunSarc(t, "list", "-p", remotePassword, "-a", url)
			for name := range files {
				if !strings.Contains(listing, "data/"+name) {
					t.Fatalf("listing lacks data/%s:\n%s", name, listing)
				}
			}
			if out := mustRunSarc(t, "verify", "-a", url); !strings.Contains(out, "integrity check PASSED") {
				t.Fatalf("verify output:\n%s", out)
			}
			dst := t.TempDir()
			mustRunSarc(t, "extract", "-p", remotePassword, "-a", url, "-o", dst)
			requireTree(t, filepath.Join(dst, "data"), files)
		})
	}
}

// TestRemoteCLIIncrementalRestore restores an incremental archive copied to a storage
// URL, which needs random access through ranged reads.
func TestRemoteCLIIncrementalRestore(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the sarc binary")
	}
	src, files := remoteTree(t)
	local := filepath.Join(t.TempDir(), "inc.sarc")
	mustRunSarc(t, "archive", "--incremental", "-p", remotePassword, "-o", local, src)
	dir := filepath.Join(t.TempDir(), "remote")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(local)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "inc.sarc"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	url := "file://" + filepath.ToSlash(withRootSlash(dir)) + "/inc.sarc"
	if listing := mustRunSarc(t, "list", "-p", remotePassword, "-a", url); !strings.Contains(listing, "data/big.bin") {
		t.Fatalf("listing:\n%s", listing)
	}
	dst := t.TempDir()
	mustRunSarc(t, "extract", "-p", remotePassword, "-a", url, "-o", dst)
	requireTree(t, filepath.Join(dst, "data"), files)
}

func TestRemoteCLIRejectsUnsupportedUses(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the sarc binary")
	}
	src, _ := remoteTree(t)
	dir := filepath.ToSlash(withRootSlash(t.TempDir()))
	url := "file://" + dir + "/a.sarc"
	cases := map[string]struct {
		args []string
		want string
	}{
		"split":             {[]string{"archive", "-p", remotePassword, "--split", "1M", "-o", url, src}, "--split"},
		"incremental":       {[]string{"archive", "--incremental", "-p", remotePassword, "-o", url, src}, "--incremental"},
		"sign":              {[]string{"sign", "-s", "unused", "-a", url}, "storage URL"},
		"extract to URL":    {[]string{"extract", "-p", remotePassword, "-a", url, "-o", "file://" + dir + "/out"}, "local --output"},
		"unknown scheme":    {[]string{"archive", "-p", remotePassword, "-o", "ftp://host/a.sarc", src}, "unsupported scheme"},
		"missing key":       {[]string{"archive", "-p", remotePassword, "-o", "s3://bucket", src}, "object key"},
		"missing directory": {[]string{"archive", "-p", remotePassword, "-o", "file://" + dir + "/no/such/a.sarc", src}, "cannot create output"},
		"missing archive":   {[]string{"list", "-p", remotePassword, "-a", "file://" + dir + "/none.sarc"}, "not found"},
	}
	for name, c := range cases {
		out, err := runSarc(t, nil, c.args...)
		if err == nil || !strings.Contains(out, c.want) {
			t.Errorf("%s: err = %v, output %q, want an error mentioning %q", name, err, out, c.want)
		}
	}
	if entries, _ := os.ReadDir(filepath.FromSlash(dir)); len(entries) != 0 {
		t.Fatalf("rejected commands left files: %v", entries)
	}
}
