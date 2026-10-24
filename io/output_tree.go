// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/iamvirul/sarc/archive"
)

// tempNameAttempts bounds retries when a random temporary name is already taken.
const tempNameAttempts = 8

// outputTree writes extracted entries under one directory. Every file, directory,
// link, and attribute change goes through an os.Root, which refuses any path that
// resolves outside the directory, so a symlink in the archive (or already in the
// output directory) can never redirect a write outside it. The directory is created
// on first use, so an archive that yields nothing leaves no trace.
type outputTree struct {
	dir          string
	root         *os.Root
	restoreOwner bool
	progress     ProgressTracker
	dirs         []pendingDir
	warned       map[string]bool
}

// pendingDir is a directory whose attributes are applied after its contents.
type pendingDir struct {
	local string
	attrs archive.Attributes
}

func newOutputTree(dir string, restoreOwner bool, progress ProgressTracker) *outputTree {
	return &outputTree{dir: dir, restoreOwner: restoreOwner, progress: progress, warned: map[string]bool{}}
}

// open creates the output directory and its root on first use.
func (t *outputTree) open() error {
	if t.root != nil {
		return nil
	}
	if err := os.MkdirAll(t.dir, 0o755); err != nil {
		return fatal(ErrCodeWriteFailed, "create output dir", err)
	}
	root, err := os.OpenRoot(t.dir)
	if err != nil {
		return fatal(ErrCodeWriteFailed, "open output dir", err)
	}
	t.root = root
	return nil
}

// close applies the attributes of extracted directories, deepest first so a parent's
// mode and time are set after its children, then releases the root.
func (t *outputTree) close() {
	if t.root == nil {
		return
	}
	sort.SliceStable(t.dirs, func(i, j int) bool {
		return strings.Count(t.dirs[i].local, string(filepath.Separator)) > strings.Count(t.dirs[j].local, string(filepath.Separator))
	})
	for _, d := range t.dirs {
		f, err := t.root.Open(d.local)
		if err != nil {
			t.warnFile(d.local, fmt.Sprintf("directory attributes not restored: %v", err))
			continue
		}
		t.applyAttributes(f, d.local, &d.attrs, 0)
		f.Close()
		t.setModTime(d.local, d.attrs.ModTime)
	}
	t.root.Close()
}

// localName validates a stored name and returns its OS form relative to the output
// directory. Absolute names, ".." elements, and names reserved on this OS are refused.
func localName(name string) (string, error) {
	local := filepath.FromSlash(name)
	if !archive.ValidEntryName(name) || !filepath.IsLocal(local) {
		return "", recoverable(ErrCodeIntegrityFail, "unsafe file name", nil)
	}
	return local, nil
}

// prepare validates name, opens the tree, and creates name's parent directories.
func (t *outputTree) prepare(name string) (string, error) {
	local, err := localName(name)
	if err != nil {
		return "", err
	}
	if err := t.open(); err != nil {
		return "", err
	}
	if parent := filepath.Dir(local); parent != "." {
		if err := t.root.MkdirAll(parent, 0o755); err != nil {
			return "", recoverable(ErrCodeWriteFailed, "create directory", err)
		}
	}
	return local, nil
}

// createTemp creates a hidden temporary file (mode 0600) beside name and returns it
// with its path relative to the output directory.
func (t *outputTree) createTemp(name string) (*os.File, string, string, error) {
	local, err := t.prepare(name)
	if err != nil {
		return nil, "", "", err
	}
	parent := filepath.Dir(local)
	for range tempNameAttempts {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, "", "", fatal(ErrCodeWriteFailed, "generate temporary name", err)
		}
		tmp := filepath.Join(parent, tempFilePrefix+hex.EncodeToString(suffix[:]))
		f, err := t.root.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", "", recoverable(ErrCodeWriteFailed, "create file", err)
		}
		return f, tmp, local, nil
	}
	return nil, "", "", recoverable(ErrCodeWriteFailed, "create file", errors.New("no free temporary name"))
}

// publish applies attrs (or fallbackPerm when the entry has none) to the open temporary
// file f, closes it, renames it to local, and sets its modification time. Rename
// replaces a file or symlink at local without following it.
func (t *outputTree) publish(f *os.File, tmp, local string, attrs *archive.Attributes, fallbackPerm fs.FileMode) error {
	t.applyAttributes(f, local, attrs, fallbackPerm)
	if err := f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := t.root.Rename(tmp, local); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	if attrs != nil {
		t.setModTime(local, attrs.ModTime)
	}
	return nil
}

// discard closes and removes a temporary file that will not be published.
func (t *outputTree) discard(f *os.File, tmp string) {
	_ = f.Close()
	_ = t.root.Remove(tmp)
}

// writeFile writes data to name atomically with attrs.
func (t *outputTree) writeFile(name string, data []byte, attrs *archive.Attributes) error {
	f, tmp, local, err := t.createTemp(name)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		t.discard(f, tmp)
		return recoverable(ErrCodeWriteFailed, "write file", err)
	}
	if err := t.publish(f, tmp, local, attrs, 0o644); err != nil {
		t.discard(f, tmp)
		return recoverable(ErrCodeWriteFailed, "write file", err)
	}
	return nil
}

// applyAttributes sets extended attributes, then ownership, then mode on the open file
// f: ownership before mode, since chown clears setuid and setgid. Failures that do not
// lose data become warnings.
func (t *outputTree) applyAttributes(f *os.File, local string, attrs *archive.Attributes, fallbackPerm fs.FileMode) {
	if attrs == nil {
		if err := f.Chmod(fallbackPerm); err != nil {
			t.warnFile(local, fmt.Sprintf("permissions not restored: %v", err))
		}
		return
	}
	if failed, err := writeXattrs(f, attrs.Xattrs); failed > 0 {
		t.warnFile(local, fmt.Sprintf("%d extended attribute(s) not restored: %v", failed, err))
	}
	t.restoreOwnership(local, attrs.Owner, f.Chown)
	if err := f.Chmod(t.mode(attrs.Mode)); err != nil {
		t.warnFile(local, fmt.Sprintf("permissions not restored: %v", err))
	}
}

// mode returns the mode to apply: setuid, setgid, and sticky bits only when ownership
// is restored too, as tar does, since they are only safe with the original owner.
func (t *outputTree) mode(mode uint32) fs.FileMode {
	if !t.restoreOwner && mode&0o7000 != 0 {
		t.warnOnce("setuid, setgid, and sticky bits were not restored; pass --preserve-owner as root to restore them")
		mode &= 0o777
	}
	return fileMode(mode)
}

// restoreOwnership changes the owner when asked to and possible, warning once when an
// archive records owners that are not restored.
func (t *outputTree) restoreOwnership(local string, owner *archive.Owner, chown func(uid, gid int) error) {
	if owner == nil {
		return
	}
	if !t.restoreOwner {
		t.warnOnce("ownership recorded in the archive was not restored; pass --preserve-owner (as root) to restore it")
		return
	}
	if err := chown(int(owner.UID), int(owner.GID)); err != nil {
		t.warnOnce(fmt.Sprintf("ownership could not be restored (restoring owners needs root): %v", err))
	}
}

func (t *outputTree) setModTime(local string, modTime int64) {
	if modTime == 0 {
		return
	}
	if err := t.root.Chtimes(local, time.Time{}, time.Unix(0, modTime)); err != nil {
		t.warnFile(local, fmt.Sprintf("modification time not restored: %v", err))
	}
}

// removeExisting removes a file or symlink at local so a link can take its place. A
// directory there is left alone, and the link then fails.
func (t *outputTree) removeExisting(local string) {
	if info, err := t.root.Lstat(local); err == nil && !info.IsDir() {
		_ = t.root.Remove(local)
	}
}

// symlink creates the symlink name pointing at target. The target is not checked:
// creating a link is harmless, and writes through it are confined by the root.
func (t *outputTree) symlink(name string, attrs *archive.Attributes) error {
	local, err := t.prepare(name)
	if err != nil {
		return err
	}
	t.removeExisting(local)
	if err := t.root.Symlink(filepath.FromSlash(attrs.LinkTarget), local); err != nil {
		return recoverable(ErrCodeWriteFailed, "create symlink", err)
	}
	t.restoreOwnership(local, attrs.Owner, func(uid, gid int) error { return t.root.Lchown(local, uid, gid) })
	return nil
}

// hardlink creates name as a hard link to the already extracted entry attrs.LinkTarget,
// whose attributes it shares.
func (t *outputTree) hardlink(name string, attrs *archive.Attributes) error {
	target, err := localName(attrs.LinkTarget)
	if err != nil {
		return err
	}
	local, err := t.prepare(name)
	if err != nil {
		return err
	}
	t.removeExisting(local)
	if err := t.root.Link(target, local); err != nil {
		return recoverable(ErrCodeWriteFailed, "create hard link", err)
	}
	return nil
}

// directory creates name and defers its attributes until close.
func (t *outputTree) directory(name string, attrs *archive.Attributes) error {
	local, err := t.prepare(name)
	if err != nil {
		return err
	}
	if err := t.root.MkdirAll(local, 0o755); err != nil {
		return recoverable(ErrCodeWriteFailed, "create directory", err)
	}
	t.dirs = append(t.dirs, pendingDir{local: local, attrs: *attrs})
	return nil
}

// special restores a directory, symlink, or hard link entry.
func (t *outputTree) special(name string, attrs *archive.Attributes) error {
	switch attrs.Kind {
	case archive.KindDirectory:
		return t.directory(name, attrs)
	case archive.KindSymlink:
		return t.symlink(name, attrs)
	case archive.KindHardlink:
		return t.hardlink(name, attrs)
	}
	return recoverable(ErrCodeIntegrityFail, "unknown entry kind", nil)
}

func (t *outputTree) warnFile(local, message string) {
	warn(t.progress, filepath.ToSlash(local), message)
}

func (t *outputTree) warnOnce(message string) {
	if !t.warned[message] {
		t.warned[message] = true
		warn(t.progress, "", message)
	}
}
