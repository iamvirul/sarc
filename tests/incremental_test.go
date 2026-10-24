// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/iamvirul/sarc/archive"
	sarcio "github.com/iamvirul/sarc/io"
)

const incrementalTestPassword = "incremental-test-pass"

// incrementalRun records the state of inputs in the archive at path.
func incrementalRun(t *testing.T, path string, inputs ...string) sarcio.IncrementalResult {
	t.Helper()
	res, err := sarcio.ArchiveIncremental(path, inputs, sarcio.IncrementalOptions{
		Password: incrementalTestPassword, UnlockPassword: incrementalTestPassword,
	})
	if err != nil {
		t.Fatalf("incremental run: %v", err)
	}
	return res
}

// openIncremental returns an extractor for the archive at path with random access.
func openIncremental(t *testing.T, path, password string, opts ...sarcio.ExtractorOption) *sarcio.SafeExtractor {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	opts = append(opts, sarcio.WithRandomAccess(f, info.Size()))
	return sarcio.NewSafeExtractor(f, password, nil, opts...)
}

// restoreIncremental extracts the archive at path and returns the restored tree.
func restoreIncremental(t *testing.T, path string) map[string][]byte {
	t.Helper()
	out := t.TempDir()
	results, err := openIncremental(t, path, incrementalTestPassword).Extract(out)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, r := range results {
		if !r.OK {
			t.Fatalf("restore %s: %v", r.Filename, r.Err)
		}
	}
	requireNoTempFilesInTree(t, out)
	return readTree(t, out)
}

func requireNoTempFilesInTree(t *testing.T, root string) {
	t.Helper()
	for name := range readTree(t, root) {
		if base := filepath.Base(name); len(base) > 13 && base[:13] == ".sarc-extract" {
			t.Fatalf("temporary file left: %s", name)
		}
	}
}

// writeFile writes content to root/name and gives it a modification time distinct from
// any earlier write, so a change is visible even on coarse-timestamp filesystems.
func writeFile(t *testing.T, root, name string, content []byte) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	bumpModTime(t, p)
}

var modTimeClock = time.Now().Add(-time.Hour)

func bumpModTime(t *testing.T, p string) {
	t.Helper()
	modTimeClock = modTimeClock.Add(2 * time.Second)
	if err := os.Chtimes(p, modTimeClock, modTimeClock); err != nil {
		t.Fatal(err)
	}
}

// treeUnder returns want restricted to names under the root/data input, as restored.
func incrementalFixture(t *testing.T) (root, archivePath string, want map[string][]byte) {
	t.Helper()
	root = t.TempDir()
	want = map[string][]byte{
		"data/docs/report.txt":   compressibleText(300 * 1024),
		"data/photos/raw.bin":    randomContent(t, 6*1024*1024),
		"data/config/app.ini":    []byte("mode=prod\n"),
		"data/empty.txt":         {},
		"data/photos/copy.bin":   nil, // filled below as a duplicate of raw.bin
		"data/logs/2026/oct.log": compressibleText(2 * 1024 * 1024),
	}
	want["data/photos/copy.bin"] = want["data/photos/raw.bin"]
	for name, content := range want {
		writeFile(t, root, name, content)
	}
	return root, filepath.Join(t.TempDir(), "backup.sarc"), want
}

func sizeOf(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func TestIncrementalFirstRunRoundtrip(t *testing.T) {
	root, archivePath, want := incrementalFixture(t)
	res := incrementalRun(t, archivePath, filepath.Join(root, "data"))
	// Directories are recorded too, so more entries than files change.
	if !res.Created || res.Session != 1 || res.Changed <= len(want) || res.AppendedBytes != sizeOf(t, archivePath) {
		t.Fatalf("unexpected first run: %+v", res)
	}
	requireSameTree(t, restoreIncremental(t, archivePath), want)
}

// TestIncrementalUnchangedRunWritesNothing is the acceptance criterion: a second run on
// an unchanged directory appends zero bytes.
func TestIncrementalUnchangedRunWritesNothing(t *testing.T) {
	root, archivePath, _ := incrementalFixture(t)
	first := incrementalRun(t, archivePath, filepath.Join(root, "data"))
	before, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	res := incrementalRun(t, archivePath, filepath.Join(root, "data"))
	if res.Changed != 0 || res.Deleted != 0 || res.AppendedBytes != 0 || res.Unchanged != first.Changed || res.Session != 1 {
		t.Fatalf("unchanged run: %+v", res)
	}
	after, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("unchanged run modified the archive")
	}
}

// TestIncrementalOneByteChangeAppendsLittle is the acceptance criterion scaled down: one
// changed byte in a large file appends about one chunk, far under 10 MB.
func TestIncrementalOneByteChangeAppendsLittle(t *testing.T) {
	root := t.TempDir()
	content := randomContent(t, 64*1024*1024)
	writeFile(t, root, "data/disk.img", content)
	archivePath := filepath.Join(t.TempDir(), "backup.sarc")
	incrementalRun(t, archivePath, filepath.Join(root, "data"))

	content[len(content)/2] ^= 0xFF
	writeFile(t, root, "data/disk.img", content)
	res := incrementalRun(t, archivePath, filepath.Join(root, "data"))
	if res.Changed != 1 || res.NewChunks > 2 || res.AppendedBytes > 10<<20 {
		t.Fatalf("one-byte change: %+v", res)
	}
	if got := restoreIncremental(t, archivePath)["data/disk.img"]; !bytes.Equal(got, content) {
		t.Fatal("restored file is not the latest version")
	}
}

func TestIncrementalDeletedFilesAreNotRestored(t *testing.T) {
	root, archivePath, want := incrementalFixture(t)
	dataDir := filepath.Join(root, "data")
	incrementalRun(t, archivePath, dataDir)

	if err := os.Remove(filepath.Join(root, "data", "config", "app.ini")); err != nil {
		t.Fatal(err)
	}
	delete(want, "data/config/app.ini")
	want["data/new.txt"] = []byte("added later\n")
	writeFile(t, root, "data/new.txt", want["data/new.txt"])
	// The new file changes, and so do the two directories whose contents changed.
	res := incrementalRun(t, archivePath, dataDir)
	if res.Deleted != 1 || res.Changed != 3 || res.Session != 2 {
		t.Fatalf("delete run: %+v", res)
	}
	requireSameTree(t, restoreIncremental(t, archivePath), want)

	list, err := openIncremental(t, archivePath, incrementalTestPassword).List()
	if err != nil {
		t.Fatal(err)
	}

	files := 0
	for _, r := range list {
		if r.Kind != archive.KindRegular {
			continue
		}
		files++
		if _, ok := want[r.Filename]; !ok || r.OriginalBytes != int64(len(want[r.Filename])) {
			t.Fatalf("list entry %+v does not match the current state", r)
		}
	}

	// A deleted name can come back in a later session.
	want["data/config/app.ini"] = []byte("mode=dev\n")
	writeFile(t, root, "data/config/app.ini", want["data/config/app.ini"])
	incrementalRun(t, archivePath, dataDir)
	requireSameTree(t, restoreIncremental(t, archivePath), want)
}

func TestIncrementalRoundtripsEdgeSizes(t *testing.T) {
	root := t.TempDir()
	want := map[string][]byte{}
	for _, size := range []int{0, 1, archive.MinCDCChunkSize - 1, archive.MinCDCChunkSize, archive.MinCDCChunkSize + 1,
		archive.MaxCDCChunkSize, archive.MaxCDCChunkSize + 1, 9*1024*1024 + 7} {
		name := filepath.ToSlash(filepath.Join("data", "f"+big.NewInt(int64(size)).String()+".bin"))
		want[name] = randomContent(t, size)
		writeFile(t, root, name, want[name])
	}
	want["data/zeros.bin"] = make([]byte, 3*archive.MaxCDCChunkSize+5)
	writeFile(t, root, "data/zeros.bin", want["data/zeros.bin"])
	archivePath := filepath.Join(t.TempDir(), "edge.sarc")
	incrementalRun(t, archivePath, filepath.Join(root, "data"))
	requireSameTree(t, restoreIncremental(t, archivePath), want)
}

// TestIncrementalDeduplicatesWithinAnArchive stores identical data once: a copy added
// later writes no new chunks, and a copy present from the start costs almost nothing.
func TestIncrementalDeduplicatesWithinAnArchive(t *testing.T) {
	root := t.TempDir()
	content := randomContent(t, 12*1024*1024)
	writeFile(t, root, "data/a.bin", content)
	single := filepath.Join(t.TempDir(), "single.sarc")
	incrementalRun(t, single, filepath.Join(root, "data"))

	writeFile(t, root, "data/b.bin", content)
	res := incrementalRun(t, single, filepath.Join(root, "data"))
	if res.NewChunks != 0 || res.AppendedBytes > 64*1024 {
		t.Fatalf("adding a copy: %+v", res)
	}

	double := filepath.Join(t.TempDir(), "double.sarc")
	incrementalRun(t, double, filepath.Join(root, "data"))
	if size := sizeOf(t, double); size > int64(len(content))+256*1024 {
		t.Fatalf("archive holding two copies of %d bytes is %d bytes", len(content), size)
	}
	tree := restoreIncremental(t, double)
	if !bytes.Equal(tree["data/a.bin"], content) || !bytes.Equal(tree["data/b.bin"], content) {
		t.Fatal("deduplicated copies do not restore")
	}
}

// TestIncrementalArchivesShareNoCiphertext archives the same data into two incremental
// archives and checks no sampled ciphertext window of one appears in the other.
func TestIncrementalArchivesShareNoCiphertext(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "data/same.bin", compressibleText(8*1024*1024))
	a, b := filepath.Join(t.TempDir(), "a.sarc"), filepath.Join(t.TempDir(), "b.sarc")
	incrementalRun(t, a, filepath.Join(root, "data"))
	incrementalRun(t, b, filepath.Join(root, "data"))
	dataA, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	dataB, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	const window = 32
	for i := 0; i < 500; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(dataA)-window)))
		if err != nil {
			t.Fatal(err)
		}
		off := int(n.Int64())
		if off < 64 {
			continue // magic and version are shared by design
		}
		if bytes.Contains(dataB, dataA[off:off+window]) {
			t.Fatalf("ciphertext window at %d appears in both archives", off)
		}
	}
}

// TestIncrementalRollbackIsRefused cuts the newest session off an archive and pairs it
// with the current header: the sealed session count exposes the rollback, even though
// the unkeyed footer checksum is consistent.
func TestIncrementalRollbackIsRefused(t *testing.T) {
	root, archivePath, _ := incrementalFixture(t)
	dataDir := filepath.Join(root, "data")
	incrementalRun(t, archivePath, dataDir)
	session1, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "data/new.txt", []byte("session two"))
	incrementalRun(t, archivePath, dataDir)
	session2, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	rolledBack := graftHeader(session2, session1)
	rolledPath := filepath.Join(t.TempDir(), "rolled.sarc")
	if err := os.WriteFile(rolledPath, rolledBack, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = openIncremental(t, rolledPath, incrementalTestPassword).Extract(t.TempDir())
	var ae *sarcio.ArchiveError
	if !errors.As(err, &ae) || ae.Code != sarcio.ErrCodeIntegrityFail {
		t.Fatalf("rolled-back archive: want %s, got %v", sarcio.ErrCodeIntegrityFail, err)
	}
}

// TestIncrementalRecoversFromInterruptedUpdate cuts an archive at points inside its
// newest session, as a crash during an update would leave it: the header still holds
// the previous session count, since an update rewrites it last. Reading falls back to
// the previous session, and the next update repairs the archive and records changes.
func TestIncrementalRecoversFromInterruptedUpdate(t *testing.T) {
	root, archivePath, want := incrementalFixture(t)
	dataDir := filepath.Join(root, "data")
	incrementalRun(t, archivePath, dataDir)
	session1, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	session1Size := int64(len(session1))
	session1Want := map[string][]byte{}
	for k, v := range want {
		session1Want[k] = v
	}
	want["data/late.bin"] = randomContent(t, 3*1024*1024)
	writeFile(t, root, "data/late.bin", want["data/late.bin"])
	incrementalRun(t, archivePath, dataDir)
	full, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	tailStart := session1Size - int64(archive.TailSize)
	for _, cut := range []int64{tailStart + 10, tailStart + 4096, (tailStart + int64(len(full))) / 2, int64(len(full)) - 1} {
		damaged := filepath.Join(t.TempDir(), "damaged.sarc")
		if err := os.WriteFile(damaged, graftHeader(session1, full[:cut]), 0o600); err != nil {
			t.Fatal(err)
		}
		got := restoreIncremental(t, damaged)
		if cut == int64(len(full))-1 {
			// Only the footer is damaged; session 2 is complete.
			requireSameTree(t, got, want)
		} else {
			requireSameTree(t, got, session1Want)
		}
		res := incrementalRun(t, damaged, dataDir)
		if !res.Repaired {
			t.Fatalf("cut at %d: update did not report a repair: %+v", cut, res)
		}
		requireSameTree(t, restoreIncremental(t, damaged), want)
		requireValidChecksum(t, damaged)
	}
}

// graftHeader returns body with header's sealed session count. Two states of one
// incremental archive share every header byte except that count, which lies within the
// FileCountSealedSize bytes from their first difference.
func graftHeader(header, body []byte) []byte {
	start := 0
	for start < len(header) && start < len(body) && header[start] == body[start] {
		start++
	}
	end := start + archive.FileCountSealedSize
	out := bytes.Clone(body)
	copy(out[start:end], header[start:end])
	return out
}

func requireValidChecksum(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := data[:len(data)-archive.FooterSize]
	sum := archive.NewArchiveChecksum()
	sum.Write(body)
	if !bytes.Equal(sum.Sum(nil), data[len(body):len(body)+32]) {
		t.Fatal("footer checksum does not match the archive")
	}
}

func TestIncrementalUpdatesKeepTheChecksumValid(t *testing.T) {
	root, archivePath, _ := incrementalFixture(t)
	dataDir := filepath.Join(root, "data")
	incrementalRun(t, archivePath, dataDir)
	requireValidChecksum(t, archivePath)
	for i := 0; i < 3; i++ {
		writeFile(t, root, "data/counter.txt", []byte{byte('0' + i)})
		incrementalRun(t, archivePath, dataDir)
		requireValidChecksum(t, archivePath)
	}
}

// TestIncrementalTamperedPackFailsItsFiles flips a byte inside the stored data: files
// using the damaged pack are refused and nothing unverified is published.
func TestIncrementalTamperedPackFailsItsFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "data/victim.bin", randomContent(t, 8*1024*1024))
	archivePath := filepath.Join(t.TempDir(), "tamper.sarc")
	incrementalRun(t, archivePath, filepath.Join(root, "data"))
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0x01
	if err := os.WriteFile(archivePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	results, err := openIncremental(t, archivePath, incrementalTestPassword).Extract(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Filename == "data/victim.bin" && r.OK {
			t.Fatalf("tampered file restored: %+v", results)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "data", "victim.bin")); !os.IsNotExist(err) {
		t.Fatal("tampered restore left the file behind")
	}
	requireNoTempFilesInTree(t, out)
}

func TestIncrementalNeedsRandomAccess(t *testing.T) {
	root, archivePath, _ := incrementalFixture(t)
	incrementalRun(t, archivePath, filepath.Join(root, "data"))
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sarcio.NewSafeExtractor(bytes.NewReader(data), incrementalTestPassword, nil).Extract(t.TempDir())
	var ae *sarcio.ArchiveError
	if !errors.As(err, &ae) || ae.Code != sarcio.ErrCodeInvalidOption {
		t.Fatalf("want %s without random access, got %v", sarcio.ErrCodeInvalidOption, err)
	}
}

// TestIncrementalUnreadableDirectoryKeepsPreviousVersions checks a directory that
// cannot be read is not recorded as deleted.
func TestIncrementalUnreadableDirectoryKeepsPreviousVersions(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix permissions and a non-root user")
	}
	root, archivePath, want := incrementalFixture(t)
	dataDir := filepath.Join(root, "data")
	incrementalRun(t, archivePath, dataDir)
	locked := filepath.Join(root, "data", "logs")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })
	res := incrementalRun(t, archivePath, dataDir)
	if res.Deleted != 0 {
		t.Fatalf("unreadable directory recorded as deleted: %+v", res)
	}
	os.Chmod(locked, 0o755)
	// The directory itself was recorded as it was (mode 000); its files were kept.
	out := t.TempDir()
	if _, err := openIncremental(t, archivePath, incrementalTestPassword).Extract(out); err != nil {
		t.Fatal(err)
	}
	restoredLogs := filepath.Join(out, "data", "logs")
	if info, err := os.Stat(restoredLogs); err != nil || info.Mode().Perm() != 0 {
		t.Fatalf("locked directory restored as %v, %v", info.Mode(), err)
	}
	if err := os.Chmod(restoredLogs, 0o755); err != nil {
		t.Fatal(err)
	}
	requireSameTree(t, readTree(t, out), want)
}

func TestIncrementalKeyFileAndPasswordCredentials(t *testing.T) {
	root, archivePath, want := incrementalFixture(t)
	dataDir := filepath.Join(root, "data")
	key := newKeyFileBytes(t)
	opts := sarcio.IncrementalOptions{
		Archiver:       []sarcio.ArchiverOption{sarcio.WithKeyFileRecipients(archive.KeyFile{Key: key, Password: incrementalTestPassword})},
		UnlockPassword: incrementalTestPassword, KeyFiles: [][]byte{key},
	}
	if _, err := sarcio.ArchiveIncremental(archivePath, []string{dataDir}, opts); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "data/more.txt", []byte("more"))
	want["data/more.txt"] = []byte("more")
	if _, err := sarcio.ArchiveIncremental(archivePath, []string{dataDir}, opts); err != nil {
		t.Fatalf("update with key file and password: %v", err)
	}
	passwordOnly := sarcio.IncrementalOptions{UnlockPassword: incrementalTestPassword}
	writeFile(t, root, "data/more.txt", []byte("changed"))
	if _, err := sarcio.ArchiveIncremental(archivePath, []string{dataDir}, passwordOnly); err == nil {
		t.Fatal("password alone updated a key file and password archive")
	}
	out := t.TempDir()
	if _, err := openIncremental(t, archivePath, incrementalTestPassword, sarcio.WithKeyFiles(key)).Extract(out); err != nil {
		t.Fatal(err)
	}
	requireSameTree(t, readTree(t, out), want)
}

func TestIncrementalRefusesUnsuitableOutputsAndOptions(t *testing.T) {
	root, _, _ := incrementalFixture(t)
	dataDir := filepath.Join(root, "data")
	normal := filepath.Join(t.TempDir(), "normal.sarc")
	f, err := os.Create(normal)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := sarcio.NewConcurrentArchiver(f, incrementalTestPassword, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Archive([]string{dataDir}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	before, _ := os.ReadFile(normal)
	if _, err := sarcio.ArchiveIncremental(normal, []string{dataDir}, sarcio.IncrementalOptions{UnlockPassword: incrementalTestPassword}); err == nil {
		t.Fatal("updated a non-incremental archive")
	}
	if after, _ := os.ReadFile(normal); !bytes.Equal(before, after) {
		t.Fatal("non-incremental archive was modified")
	}

	solid := sarcio.DefaultCompressionOptions()
	solid.Solid = true
	_, err = sarcio.ArchiveIncremental(filepath.Join(t.TempDir(), "s.sarc"), []string{dataDir}, sarcio.IncrementalOptions{
		Password: incrementalTestPassword, Archiver: []sarcio.ArchiverOption{sarcio.WithCompression(solid)},
	})
	var ae *sarcio.ArchiveError
	if !errors.As(err, &ae) || ae.Code != sarcio.ErrCodeInvalidOption {
		t.Fatalf("solid incremental: want %s, got %v", sarcio.ErrCodeInvalidOption, err)
	}

	missing := filepath.Join(t.TempDir(), "never.sarc")
	if _, err := sarcio.ArchiveIncremental(missing, []string{filepath.Join(root, "absent")}, sarcio.IncrementalOptions{Password: incrementalTestPassword}); err == nil {
		t.Fatal("missing input accepted")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("failed creation left an archive behind")
	}
}
