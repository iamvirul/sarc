// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
	sarcio "github.com/iamvirul/sarc/io"
)

func newKeyFileBytes(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, crypto.MinKeyFileSize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// archiveWithOptions archives two files with password (empty for none) and opts.
func archiveWithOptions(t *testing.T, password string, opts ...sarcio.ArchiverOption) ([]byte, map[string][]byte) {
	t.Helper()
	dir := t.TempDir()
	contents := map[string][]byte{
		"ledger.csv": compressibleText(40 * 1024),
		"photo.raw":  randomContent(t, 150*1024),
	}
	var paths []string
	for name, content := range contents {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	var buf bytes.Buffer
	ca, err := sarcio.NewConcurrentArchiver(&buf, password, 2, nil, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Archive(paths); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), contents
}

func extractWithOptions(t *testing.T, data []byte, password string, opts ...sarcio.ExtractorOption) (map[string][]byte, error) {
	t.Helper()
	outDir := filepath.Join(t.TempDir(), "out")
	results, err := sarcio.NewSafeExtractor(bytes.NewReader(data), password, nil, opts...).Extract(outDir)
	if err != nil {
		if len(results) != 0 {
			t.Fatalf("%d results alongside error %v", len(results), err)
		}
		if _, statErr := os.Stat(outDir); !os.IsNotExist(statErr) {
			t.Fatalf("output written without a valid credential: %v", statErr)
		}
		return nil, err
	}
	got := make(map[string][]byte, len(results))
	for _, r := range results {
		content, readErr := os.ReadFile(filepath.Join(outDir, r.Filename))
		if readErr != nil {
			t.Fatal(readErr)
		}
		got[r.Filename] = content
	}
	return got, nil
}

func requireSameContents(t *testing.T, got, want map[string][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d files, want %d", len(got), len(want))
	}
	for name, content := range want {
		if !bytes.Equal(got[name], content) {
			t.Fatalf("%s: content mismatch", name)
		}
	}
}

// requireAuthFailure checks err is a fatal AUTH_FAILED whose message names accepts.
func requireAuthFailure(t *testing.T, err error, accepts string) {
	t.Helper()
	var ae *sarcio.ArchiveError
	if !errors.As(err, &ae) || ae.Code != sarcio.ErrCodeAuthFailed || !ae.IsFatal() {
		t.Fatalf("want fatal %s, got %v", sarcio.ErrCodeAuthFailed, err)
	}
	if !strings.HasSuffix(ae.Message, "accepts: "+accepts) {
		t.Fatalf("message %q does not name accepted credentials %q", ae.Message, accepts)
	}
}

func TestKeyFileArchiveOpensWithKeyFileOnly(t *testing.T) {
	key := newKeyFileBytes(t)
	data, contents := archiveWithOptions(t, "", sarcio.WithKeyFileRecipients(archive.KeyFile{Key: key}))

	got, err := extractWithOptions(t, data, "", sarcio.WithKeyFiles(key))
	if err != nil {
		t.Fatal(err)
	}
	requireSameContents(t, got, contents)

	_, err = extractWithOptions(t, data, recipientsTestPassword)
	requireAuthFailure(t, err, "key file")
	_, err = extractWithOptions(t, data, "", sarcio.WithKeyFiles(newKeyFileBytes(t)))
	requireAuthFailure(t, err, "key file")
}

func TestKeyFileAndPasswordArchiveNeedsBoth(t *testing.T) {
	key := newKeyFileBytes(t)
	data, contents := archiveWithOptions(t, "",
		sarcio.WithKeyFileRecipients(archive.KeyFile{Key: key, Password: recipientsTestPassword}))

	got, err := extractWithOptions(t, data, recipientsTestPassword, sarcio.WithKeyFiles(key))
	if err != nil {
		t.Fatal(err)
	}
	requireSameContents(t, got, contents)

	for name, attempt := range map[string]struct {
		password string
		keys     [][]byte
	}{
		"key file only":       {"", [][]byte{key}},
		"password only":       {recipientsTestPassword, nil},
		"key, wrong password": {"wrong-password-1", [][]byte{key}},
		"wrong key, password": {recipientsTestPassword, [][]byte{newKeyFileBytes(t)}},
	} {
		_, err := extractWithOptions(t, data, attempt.password, sarcio.WithKeyFiles(attempt.keys...))
		if err == nil {
			t.Fatalf("%s: archive opened", name)
		}
		requireAuthFailure(t, err, "key file + password")
	}
}

func TestKeyFileCombinesWithOtherRecipients(t *testing.T) {
	key, bob := newKeyFileBytes(t), newAgeIdentity(t)
	data, contents := archiveWithOptions(t, recipientsTestPassword,
		sarcio.WithKeyFileRecipients(archive.KeyFile{Key: key}), sarcio.WithAgeRecipients(bob.Recipient()))

	for name, opener := range map[string]struct {
		password string
		opts     []sarcio.ExtractorOption
	}{
		"password":     {recipientsTestPassword, nil},
		"key file":     {"", []sarcio.ExtractorOption{sarcio.WithKeyFiles(key)}},
		"age identity": {"", []sarcio.ExtractorOption{sarcio.WithIdentities(bob)}},
	} {
		got, err := extractWithOptions(t, data, opener.password, opener.opts...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		requireSameContents(t, got, contents)
	}
	_, err := extractWithOptions(t, data, "wrong-password-1",
		sarcio.WithKeyFiles(newKeyFileBytes(t)), sarcio.WithIdentities([]age.Identity{newAgeIdentity(t)}...))
	requireAuthFailure(t, err, "password, key file, age or SSH identity")
}

// TestKeyFileArchiveDoesNotContainTheKey confirms the key file bytes appear nowhere in
// the archive.
func TestKeyFileArchiveDoesNotContainTheKey(t *testing.T) {
	key := newKeyFileBytes(t)
	data, _ := archiveWithOptions(t, "", sarcio.WithKeyFileRecipients(archive.KeyFile{Key: key}))
	if bytes.Contains(data, key[:16]) {
		t.Fatal("archive contains key file bytes")
	}
}
