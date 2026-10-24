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

// inputFile is an entry to archive: its path on disk, the slash-separated name stored
// for it, and its attributes. Only regular files carry data.
type inputFile struct {
	path  string
	name  string
	attrs archive.Attributes
}

// regular reports whether in is a regular file, whose content is archived.
func (in inputFile) regular() bool { return in.attrs.Kind == archive.KindRegular }

// skippedInput is an archive argument, or an entry inside a directory argument, that
// is not archived, or a notice about one that is. name is its stored name when known.
// unreadable marks a failure to read it, as opposed to an entry that is never archived
// (such as a device); an incremental update keeps the previous versions of unreadable
// files and directories. warning marks a notice about an entry that is still archived.
type skippedInput struct {
	path       string
	name       string
	err        error
	unreadable bool
	warning    bool
}

// walkOptions selects the optional attributes expandInputs records.
type walkOptions struct {
	owner bool // record uid and gid
}

// expandInputs resolves archive arguments into entries. A file argument (a symlink is
// followed) is stored under its base name. A directory is walked in lexical order and
// stored, with everything in it, under its path relative to the directory's parent, so
// "data/" stores "data", "data/a.txt", and "data/sub/b.txt"; "." stores paths relative
// to itself. Inside directories, symlinks are stored as links, and a second path to an
// already listed file is stored as a hard link to it. Devices, sockets, and pipes,
// unreadable entries, and names that cannot be stored safely are returned as skipped.
func expandInputs(paths []string, opts walkOptions) ([]inputFile, []skippedInput) {
	w := walker{opts: opts, linked: map[fileID]string{}}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			w.skip(skippedInput{path: p, err: recoverable(ErrCodeReadFailed, "stat file", err), unreadable: true})
			continue
		}
		if !info.IsDir() {
			w.add(p, info.Name(), info)
			continue
		}
		w.walkDir(p)
	}
	return w.files, w.skipped
}

// walker accumulates the entries of expandInputs.
type walker struct {
	opts    walkOptions
	files   []inputFile
	skipped []skippedInput
	linked  map[fileID]string // stored name of the first path to each multiply linked file
}

func (w *walker) skip(s skippedInput) { w.skipped = append(w.skipped, s) }

func (w *walker) walkDir(dir string) {
	prefix := directoryPrefix(dir)
	root := dir
	if info, err := os.Lstat(dir); err == nil && info.Mode()&fs.ModeSymlink != 0 {
		// A trailing separator makes WalkDir descend into a symlinked directory argument.
		root = dir + string(filepath.Separator)
	}
	walkErr := filepath.WalkDir(root, func(walked string, d fs.DirEntry, err error) error {
		name := storedName(prefix, root, walked)
		if err != nil {
			w.skip(skippedInput{path: walked, name: name, err: recoverable(ErrCodeReadFailed, "read directory", err), unreadable: true})
			if d != nil && d.IsDir() && walked != root {
				return fs.SkipDir
			}
			return nil
		}
		if name == "" {
			return nil // the "." argument itself
		}
		info, err := d.Info()
		if err != nil {
			w.skip(skippedInput{path: walked, name: name, err: recoverable(ErrCodeReadFailed, "stat file", err), unreadable: true})
			return nil
		}
		if walked == root && info.Mode()&fs.ModeSymlink != 0 {
			if info, err = os.Stat(walked); err != nil {
				return nil
			}
		}
		w.add(walked, name, info)
		return nil
	})
	if walkErr != nil {
		w.skip(skippedInput{path: dir, err: recoverable(ErrCodeReadFailed, "walk directory", walkErr), unreadable: true})
	}
}

// add records the entry at p, stored as name, or why it is skipped.
func (w *walker) add(p, name string, info fs.FileInfo) {
	if !archive.ValidEntryName(name) {
		w.skip(skippedInput{path: p, err: recoverable(ErrCodeReadFailed, "unsupported file name", nil)})
		return
	}
	attrs := archive.Attributes{Mode: unixMode(info.Mode()), ModTime: info.ModTime().UnixNano()}
	switch mode := info.Mode(); {
	case mode.IsRegular():
		if id, ok := linkedFileID(info); ok {
			if first, seen := w.linked[id]; seen {
				attrs.Kind, attrs.LinkTarget = archive.KindHardlink, first
				break
			}
			w.linked[id] = name
		}
	case mode.IsDir():
		attrs.Kind = archive.KindDirectory
	case mode&fs.ModeSymlink != 0:
		target, err := os.Readlink(p)
		if err != nil {
			w.skip(skippedInput{path: p, name: name, err: recoverable(ErrCodeReadFailed, "read symlink", err), unreadable: true})
			return
		}
		if target == "" || len(target) > archive.MaxLinkTargetLen {
			w.skip(skippedInput{path: p, name: name, err: recoverable(ErrCodeReadFailed, "unsupported symlink target", nil)})
			return
		}
		attrs.Kind, attrs.LinkTarget = archive.KindSymlink, filepath.ToSlash(target)
	default:
		w.skip(skippedInput{path: p, name: name, err: recoverable(ErrCodeReadFailed, "device, socket, or pipe: not archived", nil)})
		return
	}
	if w.opts.owner {
		attrs.Owner = fileOwner(info)
	}
	xattrs, err := readXattrs(p)
	switch {
	case err != nil:
		w.skip(skippedInput{path: p, name: name, err: recoverable(ErrCodeReadFailed, "extended attributes not stored", err), warning: true})
	case archive.XattrsSize(xattrs) > archive.MaxXattrsSize || len(xattrs) > archive.MaxXattrs:
		w.skip(skippedInput{path: p, name: name, warning: true,
			err: recoverable(ErrCodeReadFailed, "extended attributes larger than 1 MiB not stored", nil)})
	default:
		attrs.Xattrs = xattrs
	}
	w.files = append(w.files, inputFile{path: p, name: name, attrs: attrs})
}

// unixMode converts a FileMode's permission and special bits to chmod form.
func unixMode(m fs.FileMode) uint32 {
	mode := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		mode |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		mode |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		mode |= 0o1000
	}
	return mode
}

// fileMode converts chmod-form mode bits to a FileMode.
func fileMode(mode uint32) fs.FileMode {
	m := fs.FileMode(mode & 0o777)
	if mode&0o4000 != 0 {
		m |= fs.ModeSetuid
	}
	if mode&0o2000 != 0 {
		m |= fs.ModeSetgid
	}
	if mode&0o1000 != 0 {
		m |= fs.ModeSticky
	}
	return m
}

// storedName returns the stored name of walked, found while walking the directory
// root whose names start with prefix. It is prefix for root itself, "" when that is
// also empty (for "."), and prefix for a path that cannot be made relative to root.
func storedName(prefix, root, walked string) string {
	rel, err := filepath.Rel(root, walked)
	if err != nil || rel == "." {
		return prefix
	}
	return path.Join(prefix, filepath.ToSlash(rel))
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

// InputTotals returns the number of entries and the total size of the regular files
// that archiving paths would read, expanding directories as the archivers do.
func InputTotals(paths []string) (int, int64) {
	files, _ := expandInputs(paths, walkOptions{})
	var total int64
	for _, f := range files {
		if !f.regular() {
			continue
		}
		if info, err := os.Stat(f.path); err == nil {
			total += info.Size()
		}
	}
	return len(files), total
}

// reportSkipped reports each skipped input to progress: as a file error, or as a
// warning for an entry that is still archived.
func reportSkipped(skipped []skippedInput, progress ProgressTracker) {
	for _, s := range skipped {
		if s.warning {
			warn(progress, s.path, s.err.(*ArchiveError).Message)
			continue
		}
		progress.FileError(s.path, s.err)
	}
}

// splitSpecial separates regular files from directories, symlinks, and hard links,
// which carry no data and are written after every file.
func splitSpecial(files []inputFile) (regular, special []inputFile) {
	for _, f := range files {
		if f.regular() {
			regular = append(regular, f)
		} else {
			special = append(special, f)
		}
	}
	return regular, special
}
