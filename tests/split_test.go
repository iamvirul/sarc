// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamvirul/sarc/archive"
	sarcio "github.com/iamvirul/sarc/io"
)

const splitTestPassword = "split-test-pass"

// TestSplitArchiveMatchesTheSingleFileArchive writes the same archive stream to one
// file and to volumes: joining the volumes gives back the stream byte for byte, so
// splitting adds only the per-volume framing.
func TestSplitArchiveMatchesTheSingleFileArchive(t *testing.T) {
	root := t.TempDir()
	want := writeTestTree(t, root)
	var single bytes.Buffer
	tee := &teeWriter{a: &single}
	base := filepath.Join(t.TempDir(), "backup.sarc")
	vw, err := sarcio.CreateVolumes(base, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	tee.b = vw
	ca, err := sarcio.NewConcurrentArchiver(tee, splitTestPassword, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Archive([]string{filepath.Join(root, "data")}); err != nil {
		t.Fatal(err)
	}
	if err := vw.Close(); err != nil {
		t.Fatal(err)
	}

	var total int64
	for _, p := range vw.Paths() {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > 1<<20 {
			t.Fatalf("%s exceeds the volume size", p)
		}
		total += info.Size()
	}
	if overhead := total - int64(single.Len()); overhead != int64(len(vw.Paths())*archive.VolumeOverhead) {
		t.Fatalf("split adds %d bytes over %d volumes", overhead, len(vw.Paths()))
	}

	vr, err := sarcio.OpenVolumes(base)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := io.ReadAll(vr)
	vr.Close()
	if err != nil || !bytes.Equal(joined, single.Bytes()) {
		t.Fatalf("joined volumes differ from the single-file archive: %v", err)
	}
	out := t.TempDir()
	if _, err := sarcio.NewSafeExtractor(bytes.NewReader(joined), splitTestPassword, nil).Extract(out); err != nil {
		t.Fatal(err)
	}
	requireSameTree(t, readTree(t, out), want)
}

// teeWriter writes to both a and b.
type teeWriter struct{ a, b io.Writer }

func (w *teeWriter) Write(p []byte) (int, error) {
	if _, err := w.a.Write(p); err != nil {
		return 0, err
	}
	return w.b.Write(p)
}

// TestSplitCLI runs the issue's workflow through the real binary.
func TestSplitCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the sarc binary")
	}
	root := t.TempDir()
	writeFile(t, root, "data/disk.img", randomContent(t, 5*1024*1024))
	writeFile(t, root, "data/notes.txt", []byte("notes"))
	dataDir := filepath.Join(root, "data")
	dir := t.TempDir()
	base := filepath.Join(dir, "backup.sarc")
	single := filepath.Join(dir, "single.sarc")

	out, err := runSarc(t, nil, "archive", "-p", splitTestPassword, "--split", "2MB", "-o", base, dataDir)
	if err != nil || !strings.Contains(out, "wrote 3 volume(s)") {
		t.Fatalf("split archive: %v\n%s", err, out)
	}
	if out, err := runSarc(t, nil, "archive", "-p", splitTestPassword, "-o", single, dataDir); err != nil {
		t.Fatalf("single archive: %v\n%s", err, out)
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Fatal("a split archive also wrote the unsplit file")
	}
	var total int64
	for i := 1; i <= 3; i++ {
		info, err := os.Stat(sarcio.VolumePath(base, i))
		if err != nil || info.Size() > 2_000_000 {
			t.Fatalf("volume %d: %v", i, err)
		}
		total += info.Size()
	}
	singleInfo, err := os.Stat(single)
	if err != nil {
		t.Fatal(err)
	}
	// Both archives use fresh random padding, so compare against a generous bound.
	if diff := total - singleInfo.Size(); diff < -16*1024 || diff > int64(3*archive.VolumeOverhead+16*1024) {
		t.Fatalf("volumes total %d bytes, single archive %d", total, singleInfo.Size())
	}
	if data, _ := os.ReadFile(single); archive.IsVolumeHeader(data) {
		t.Fatal("an unsplit archive carries volume framing")
	}

	for _, from := range []string{sarcio.VolumePath(base, 2), base} {
		dest := filepath.Join(t.TempDir(), "out")
		if out, err := runSarc(t, nil, "extract", "-p", splitTestPassword, "-a", from, "-o", dest); err != nil {
			t.Fatalf("extract from %s: %v\n%s", from, err, out)
		}
		got := readTree(t, dest)
		if len(got) != 2 || len(got["data/disk.img"]) != 5*1024*1024 {
			t.Fatalf("extract from %s restored %v", from, keys(got))
		}
	}
	if out, err := runSarc(t, nil, "verify", "-a", sarcio.VolumePath(base, 3)); err != nil || !strings.Contains(out, "all 3 volume(s) present and intact") {
		t.Fatalf("verify: %v\n%s", err, out)
	}

	// cat backup.sarc.* | sarc extract -a -
	var joined []byte
	for i := 1; i <= 3; i++ {
		b, err := os.ReadFile(sarcio.VolumePath(base, i))
		if err != nil {
			t.Fatal(err)
		}
		joined = append(joined, b...)
	}
	if out, err := runSarc(t, joined, "extract", "-p", splitTestPassword, "-a", "-", "-o", filepath.Join(t.TempDir(), "out")); err != nil {
		t.Fatalf("extract concatenated volumes from stdin: %v\n%s", err, out)
	}

	second := sarcio.VolumePath(base, 2)
	saved, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(second); err != nil {
		t.Fatal(err)
	}
	if out, err := runSarc(t, nil, "extract", "-p", splitTestPassword, "-a", base, "-o", filepath.Join(t.TempDir(), "out")); err == nil ||
		!strings.Contains(out, "volume 2 (") || !strings.Contains(out, "missing") {
		t.Fatalf("missing volume: %v\n%s", err, out)
	}
	corrupt := bytes.Clone(saved)
	corrupt[len(corrupt)/2] ^= 1
	if err := os.WriteFile(second, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runSarc(t, nil, "verify", "-a", base); err == nil || !strings.Contains(out, "volume 2 (") || !strings.Contains(out, "corrupted") {
		t.Fatalf("corrupted volume: %v\n%s", err, out)
	}

	if out, err := runSarc(t, nil, "archive", "-p", splitTestPassword, "--split", "2MB", "-o", "-", dataDir); err == nil {
		t.Fatalf("--split to stdout accepted:\n%s", out)
	}
	if out, err := runSarc(t, nil, "archive", "-p", splitTestPassword, "--split", "2MB", "--incremental", "-o", filepath.Join(dir, "inc"), dataDir); err == nil {
		t.Fatalf("--split --incremental accepted:\n%s", out)
	}
}

func TestSignedSplitArchiveVerifies(t *testing.T) {
	signer := newSSHSigner(t)
	src := filepath.Join(t.TempDir(), "doc.bin")
	if err := os.WriteFile(src, randomContent(t, 3*1024*1024), 0o644); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "signed.sarc")
	vw, err := sarcio.CreateVolumes(base, 512*1024)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := sarcio.NewConcurrentArchiver(vw, splitTestPassword, 2, nil, sarcio.WithSigner(signer))
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Archive([]string{src}); err != nil {
		t.Fatal(err)
	}
	if err := vw.Close(); err != nil {
		t.Fatal(err)
	}
	vr, err := sarcio.OpenVolumes(base)
	if err != nil {
		t.Fatal(err)
	}
	defer vr.Close()
	rep, err := sarcio.VerifyArchive(vr)
	if err != nil || !rep.ChecksumOK || rep.SignatureErr != nil || !bytes.Equal(rep.Signer.Marshal(), signer.PublicKey().Marshal()) {
		t.Fatalf("signed split archive: %+v %v", rep, err)
	}
	if vr.Volumes() != len(vw.Paths()) {
		t.Fatalf("verified %d of %d volumes", vr.Volumes(), len(vw.Paths()))
	}
}
