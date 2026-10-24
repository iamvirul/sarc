// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runSarc(t *testing.T, stdin []byte, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(sarcBinary(t), args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestIncrementalCLI runs the issue's workflow through the real binary: create, rerun
// with no change, change and delete files, list, and restore.
func TestIncrementalCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the sarc binary")
	}
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	writeFile(t, root, "data/keep.txt", []byte("keep"))
	writeFile(t, root, "data/sub/edit.bin", randomContent(t, 3*1024*1024))
	writeFile(t, root, "data/gone.txt", []byte("gone"))
	archivePath := filepath.Join(t.TempDir(), "backup.sarc")
	archive := func() string {
		t.Helper()
		out, err := runSarc(t, nil, "archive", "-p", incrementalTestPassword, "--incremental", "-o", archivePath, dataDir)
		if err != nil {
			t.Fatalf("archive: %v\n%s", err, out)
		}
		return out
	}

	// Three files and the two directories holding them.
	if out := archive(); !strings.Contains(out, "created incremental archive: session 1, 5 file(s)") {
		t.Fatalf("create output:\n%s", out)
	}
	if out := archive(); !strings.Contains(out, "no changes since session 1; archive not modified") {
		t.Fatalf("unchanged output:\n%s", out)
	}
	edited := randomContent(t, 3*1024*1024)
	writeFile(t, root, "data/sub/edit.bin", edited)
	if err := os.Remove(filepath.Join(dataDir, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	// edit.bin, and data whose listing lost gone.txt; data/sub and keep.txt are unchanged.
	if out := archive(); !strings.Contains(out, "session 2: 2 file(s) changed") || !strings.Contains(out, "2 unchanged, 1 deleted") {
		t.Fatalf("update output:\n%s", out)
	}

	list, err := runSarc(t, nil, "list", "-p", incrementalTestPassword, "-a", archivePath)
	if err != nil || strings.Contains(list, "gone.txt") || !strings.Contains(list, "data/sub/edit.bin") || !strings.Contains(list, "4 entries") {
		t.Fatalf("list: %v\n%s", err, list)
	}
	if out, err := runSarc(t, nil, "verify", "-a", archivePath); err != nil || !strings.Contains(out, "PASSED") {
		t.Fatalf("verify: %v\n%s", err, out)
	}

	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	// Redirected from a file, stdin is seekable and works; a pipe is refused clearly.
	out := filepath.Join(t.TempDir(), "out")
	redirect := exec.Command(sarcBinary(t), "extract", "-p", incrementalTestPassword, "-a", "-", "-o", out)
	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	redirect.Stdin = f
	if res, err := redirect.CombinedOutput(); err != nil {
		t.Fatalf("extract from redirected stdin: %v\n%s", err, res)
	}
	got := readTree(t, out)
	if len(got) != 2 || !bytes.Equal(got["data/sub/edit.bin"], edited) || string(got["data/keep.txt"]) != "keep" {
		t.Fatalf("restored tree has %d files: %v", len(got), keys(got))
	}
	if res, err := runSarc(t, data, "extract", "-p", incrementalTestPassword, "-a", "-", "-o", t.TempDir()); err == nil ||
		!strings.Contains(res, "must be read from a file") {
		t.Fatalf("piped incremental extract: %v\n%s", err, res)
	}
	if res, err := runSarc(t, nil, "archive", "-p", incrementalTestPassword, "--incremental", "-o", "-", dataDir); err == nil ||
		!strings.Contains(res, "not stdout") {
		t.Fatalf("incremental to stdout: %v\n%s", err, res)
	}
	if res, err := runSarc(t, nil, "archive", "-p", incrementalTestPassword, "--incremental", "--solid", "-o", archivePath, dataDir); err == nil {
		t.Fatalf("--incremental --solid accepted:\n%s", res)
	}
}
