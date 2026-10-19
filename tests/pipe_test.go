// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const pipeTestPassword = "pipe-test-password"

var (
	sarcBinaryOnce sync.Once
	sarcBinaryPath string
	sarcBinaryErr  error
)

// sarcBinary builds the sarc CLI once per test run and returns its path.
func sarcBinary(t *testing.T) string {
	t.Helper()
	sarcBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sarc-pipe-test-*")
		if err != nil {
			sarcBinaryErr = err
			return
		}
		sarcBinaryPath = filepath.Join(dir, "sarc")
		out, err := exec.Command("go", "build", "-o", sarcBinaryPath, "github.com/iamvirul/sarc/cmd/sarc").CombinedOutput()
		if err != nil {
			sarcBinaryErr = err
			t.Logf("go build output:\n%s", out)
		}
	})
	if sarcBinaryErr != nil {
		t.Fatalf("build sarc: %v", sarcBinaryErr)
	}
	return sarcBinaryPath
}

// TestArchivePipedIntoExtract runs `sarc archive -o - | sarc extract -a -` through real
// OS pipes, with no archive file on disk at any point.
func TestArchivePipedIntoExtract(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the sarc binary")
	}
	bin := sarcBinary(t)
	dir := t.TempDir()
	contents := map[string][]byte{
		"large.bin": randomContent(t, 6*1024*1024),
		"notes.txt": compressibleText(200 * 1024),
		"tiny.cfg":  []byte("key=value\n"),
	}
	var paths []string
	for name, content := range contents {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	outDir := filepath.Join(dir, "out")

	archive := exec.Command(bin, append([]string{"archive", "-p", pipeTestPassword, "-o", "-"}, paths...)...)
	extract := exec.Command(bin, "extract", "-p", pipeTestPassword, "-a", "-", "-o", outDir)
	pipe, err := archive.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	extract.Stdin = pipe
	var archiveErr, extractOut bytes.Buffer
	archive.Stderr = &archiveErr
	extract.Stdout = &extractOut
	extract.Stderr = &extractOut

	if err := extract.Start(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Run(); err != nil {
		t.Fatalf("archive: %v\n%s", err, archiveErr.String())
	}
	if err := extract.Wait(); err != nil {
		t.Fatalf("extract: %v\n%s", err, extractOut.String())
	}
	for name, want := range contents {
		got, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: content mismatch after pipe (%v)", name, err)
		}
	}
	requireNoTempFiles(t, outDir)
}

func TestVerifyAndListReadStdin(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the sarc binary")
	}
	bin := sarcBinary(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(src, compressibleText(50*1024), 0o644); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(dir, "a.sarc")
	if out, err := exec.Command(bin, "archive", "-p", pipeTestPassword, "-o", archivePath, src).CombinedOutput(); err != nil {
		t.Fatalf("archive: %v\n%s", err, out)
	}
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	run := func(stdin []byte, args ...string) (string, error) {
		cmd := exec.Command(bin, args...)
		cmd.Stdin = bytes.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run(data, "verify", "-a", "-"); err != nil || !strings.Contains(out, "PASSED") {
		t.Fatalf("verify from stdin: %v\n%s", err, out)
	}
	if out, err := run(data, "list", "-p", pipeTestPassword, "-a", "-"); err != nil || !strings.Contains(out, "data.txt") {
		t.Fatalf("list from stdin: %v\n%s", err, out)
	}
	corrupted := append([]byte{}, data...)
	corrupted[len(corrupted)/2] ^= 0xFF
	if out, err := run(corrupted, "verify", "-a", "-"); err == nil || !strings.Contains(out, "FAILED") {
		t.Fatalf("verify accepted a corrupted stream:\n%s", out)
	}
}
