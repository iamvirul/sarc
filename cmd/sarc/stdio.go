// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	sarcio "github.com/iamvirul/sarc/io"
)

// stdioPath as --archive or archive --output means stdin or stdout, for pipelines.
const stdioPath = "-"

// archiveReadBufferSize batches the extractor's many small reads into large syscalls.
const archiveReadBufferSize = 1 << 20

var (
	errTerminalOutput = errors.New("refusing to write an archive to a terminal; redirect or pipe stdout")
	errTerminalInput  = errors.New("refusing to read an archive from a terminal; redirect or pipe stdin")
)

// isTerminal reports whether f is a character device such as an interactive terminal.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// archiveInput is an opened --archive source.
type archiveInput struct {
	io.Reader
	file *os.File // nil for stdin, which is left open
}

// openArchiveInput opens path for reading, or stdin for "-", behind a large buffer.
func openArchiveInput(path string) (*archiveInput, error) {
	if path == stdioPath {
		if isTerminal(os.Stdin) {
			return nil, errTerminalInput
		}
		return &archiveInput{Reader: bufio.NewReaderSize(os.Stdin, archiveReadBufferSize)}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open archive: %w", err)
	}
	return &archiveInput{Reader: bufio.NewReaderSize(f, archiveReadBufferSize), file: f}, nil
}

// Close closes the underlying file; stdin is left open.
func (in *archiveInput) Close() error {
	if in.file == nil {
		return nil
	}
	return in.file.Close()
}

// archiveOutput is an opened archive --output destination.
type archiveOutput struct {
	io.Writer
	file     *os.File // the output file, nil for stdout
	progress io.Writer
}

// createArchiveOutput creates path, or uses stdout for "-". When the archive goes to
// stdout, progress is written to stderr so it cannot corrupt the stream.
func createArchiveOutput(path string) (*archiveOutput, error) {
	if path == stdioPath {
		if isTerminal(os.Stdout) {
			return nil, errTerminalOutput
		}
		return &archiveOutput{Writer: os.Stdout, progress: os.Stderr}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("cannot create output file: %w", err)
	}
	return &archiveOutput{Writer: f, file: f, progress: os.Stdout}, nil
}

// Close closes the output file; stdout is left open.
func (out *archiveOutput) Close() error {
	if out.file == nil {
		return nil
	}
	return out.file.Close()
}

// randomAccess returns the extractor option giving random access to a regular archive
// file, including stdin redirected from one, which incremental archives need. It
// returns none for a pipe.
func (in *archiveInput) randomAccess() []sarcio.ExtractorOption {
	f := in.file
	if f == nil {
		f = os.Stdin
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	return []sarcio.ExtractorOption{sarcio.WithRandomAccess(f, info.Size())}
}
