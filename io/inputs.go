// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/iamvirul/sarc/archive"
)

// inputFile is a regular file to archive and the slash-separated name stored for it.
type inputFile struct {
	path string
	name string
}

// skippedInput is an archive argument, or an entry inside a directory argument, that
// is not archived.
type skippedInput struct {
	path string
	err  error
}

// expandInputs resolves archive arguments into regular files. A file argument (a
// symlink is followed) is stored under its base name. A directory is walked in lexical
// order and each regular file is stored under its path relative to the directory's
// parent, so "data/" stores "data/a.txt" and "data/sub/b.txt"; "." stores paths
// relative to itself. Symlinks, devices, and sockets inside a directory, unreadable
// arguments, and names that cannot be stored safely are returned as skipped.
func expandInputs(paths []string) ([]inputFile, []skippedInput) {
	var files []inputFile
	var skipped []skippedInput
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			skipped = append(skipped, skippedInput{p, recoverable(ErrCodeReadFailed, "stat file", err)})
			continue
		}
		if !info.IsDir() {
			files, skipped = appendInput(files, skipped, p, info.Name(), info)
			continue
		}
		prefix := directoryPrefix(p)
		walkErr := filepath.WalkDir(p, func(walked string, d fs.DirEntry, err error) error {
			if err != nil {
				skipped = append(skipped, skippedInput{walked, recoverable(ErrCodeReadFailed, "read directory", err)})
				if d != nil && d.IsDir() && walked != p {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(p, walked)
			if err != nil {
				skipped = append(skipped, skippedInput{walked, recoverable(ErrCodeReadFailed, "resolve path", err)})
				return nil
			}
			info, err := d.Info()
			if err != nil {
				skipped = append(skipped, skippedInput{walked, recoverable(ErrCodeReadFailed, "stat file", err)})
				return nil
			}
			files, skipped = appendInput(files, skipped, walked, path.Join(prefix, filepath.ToSlash(rel)), info)
			return nil
		})
		if walkErr != nil {
			skipped = append(skipped, skippedInput{p, recoverable(ErrCodeReadFailed, "walk directory", walkErr)})
		}
	}
	return files, skipped
}

// appendInput adds the file at p, stored as name, or records why it is skipped.
func appendInput(files []inputFile, skipped []skippedInput, p, name string, info fs.FileInfo) ([]inputFile, []skippedInput) {
	switch {
	case !info.Mode().IsRegular():
		return files, append(skipped, skippedInput{p, recoverable(ErrCodeReadFailed, "not a regular file", nil)})
	case !archive.ValidEntryName(name):
		return files, append(skipped, skippedInput{p, recoverable(ErrCodeReadFailed, "unsupported file name", nil)})
	}
	return append(files, inputFile{path: p, name: name}), skipped
}

// directoryPrefix returns the stored name prefix for a directory argument: its base
// name, or nothing for ".", "..", and filesystem roots.
func directoryPrefix(dir string) string {
	base := filepath.Base(filepath.Clean(dir))
	if base == "." || base == ".." || strings.HasSuffix(base, string(filepath.Separator)) {
		return ""
	}
	return filepath.ToSlash(base)
}

// InputTotals returns the number and total size of the regular files that archiving
// paths would read, expanding directories as the archivers do.
func InputTotals(paths []string) (int, int64) {
	files, _ := expandInputs(paths)
	var total int64
	for _, f := range files {
		if info, err := os.Stat(f.path); err == nil {
			total += info.Size()
		}
	}
	return len(files), total
}

// reportSkipped reports each skipped input to progress as a file error.
func reportSkipped(skipped []skippedInput, progress ProgressTracker) {
	for _, s := range skipped {
		progress.FileError(s.path, s.err)
	}
}
