// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/iamvirul/sarc/archive"
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
	file    *os.File             // nil for stdin, which is left open, and for split archives
	volumes *sarcio.VolumeReader // set for a split archive
}

// openArchiveInput opens path for reading, or stdin for "-", behind a large buffer. A
// split archive, named by any of its volumes or its base name, or arriving on stdin as
// concatenated volumes, is read as the joined archive.
func openArchiveInput(path string) (*archiveInput, error) {
	if path == stdioPath {
		if isTerminal(os.Stdin) {
			return nil, errTerminalInput
		}
		stdin := bufio.NewReaderSize(os.Stdin, archiveReadBufferSize)
		if head, _ := stdin.Peek(archive.VolumeHeaderSize); archive.IsVolumeHeader(head) {
			return volumeInput(sarcio.NewVolumeStreamReader(stdin)), nil
		}
		return &archiveInput{Reader: stdin}, nil
	}
	if base, ok := sarcio.FindVolumes(path); ok {
		vr, err := sarcio.OpenVolumes(base)
		if err != nil {
			return nil, err
		}
		return volumeInput(vr), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open archive: %w", err)
	}
	return &archiveInput{Reader: bufio.NewReaderSize(f, archiveReadBufferSize), file: f}, nil
}

func volumeInput(vr *sarcio.VolumeReader) *archiveInput {
	return &archiveInput{Reader: bufio.NewReaderSize(vr, archiveReadBufferSize), volumes: vr}
}

// Close closes the underlying file; stdin is left open.
func (in *archiveInput) Close() error {
	switch {
	case in.volumes != nil:
		return in.volumes.Close()
	case in.file != nil:
		return in.file.Close()
	}
	return nil
}

// archiveOutput is an opened archive --output destination.
type archiveOutput struct {
	io.Writer
	file     *os.File             // the output file, nil for stdout and split archives
	volumes  *sarcio.VolumeWriter // set when splitting into volumes
	progress io.Writer
	closed   bool
}

// createArchiveOutput creates path, or uses stdout for "-". When the archive goes to
// stdout, progress is written to stderr so it cannot corrupt the stream. With a split
// size, it writes volumes path.001, path.002, and so on of at most that size.
func createArchiveOutput(path string, split int64) (*archiveOutput, error) {
	if split > 0 {
		if path == stdioPath {
			return nil, errors.New("--split writes volume files, so it needs an --output path, not stdout")
		}
		vw, err := sarcio.CreateVolumes(path, split)
		if err != nil {
			return nil, err
		}
		return &archiveOutput{Writer: vw, volumes: vw, progress: os.Stdout}, nil
	}
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

// Close closes the output file or finishes the last volume; stdout is left open. Only
// the first call does anything.
func (out *archiveOutput) Close() error {
	if out.closed {
		return nil
	}
	out.closed = true
	switch {
	case out.volumes != nil:
		return out.volumes.Close()
	case out.file != nil:
		return out.file.Close()
	}
	return nil
}

// randomAccess returns the extractor option giving random access to a regular archive
// file, including stdin redirected from one, which incremental archives need. It
// returns none for a pipe.
func (in *archiveInput) randomAccess() []sarcio.ExtractorOption {
	if in.volumes != nil {
		return nil
	}
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
