// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestIsTerminalFalseForRegularFile(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "plain"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Fatal("regular file reported as a terminal")
	}
}

func TestCreateArchiveOutputFileSendsProgressToStdout(t *testing.T) {
	out, err := createArchiveOutput(context.Background(), filepath.Join(t.TempDir(), "a.sarc"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if out.file == nil || out.progress != os.Stdout {
		t.Fatal("file output should keep progress on stdout")
	}
}

func TestOpenArchiveInputMissingFile(t *testing.T) {
	if _, err := openArchiveInput(context.Background(), filepath.Join(t.TempDir(), "missing.sarc")); err == nil {
		t.Fatal("opened a missing archive")
	}
}
