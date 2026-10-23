// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamvirul/sarc/archive"
)

const testVolumeSize = MinVolumeSize

func testPayload(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// writeVolumes splits data into volumes of testVolumeSize under dir, writing it in
// random-sized pieces, and returns the base name.
func writeVolumes(t *testing.T, dir string, data []byte) string {
	t.Helper()
	base := filepath.Join(dir, "backup.sarc")
	vw, err := CreateVolumes(base, testVolumeSize)
	if err != nil {
		t.Fatal(err)
	}
	for rest := data; len(rest) > 0; {
		n := min(len(rest), 1+mrand.IntN(3*testVolumeSize/2))
		if _, err := vw.Write(rest[:n]); err != nil {
			t.Fatal(err)
		}
		rest = rest[n:]
	}
	if err := vw.Close(); err != nil {
		t.Fatal(err)
	}
	return base
}

func readVolumes(t *testing.T, base string) ([]byte, error) {
	t.Helper()
	vr, err := OpenVolumes(base)
	if err != nil {
		return nil, err
	}
	defer vr.Close()
	return io.ReadAll(vr)
}

func requireVolumeError(t *testing.T, err error, index int, problem string) {
	t.Helper()
	var ve *VolumeError
	if !errors.As(err, &ve) || ve.Index != index || !strings.Contains(ve.Problem, problem) {
		t.Fatalf("want volume %d %q, got %v", index, problem, err)
	}
}

func TestVolumesRoundtrip(t *testing.T) {
	capacity := testVolumeSize - archive.VolumeOverhead
	for name, size := range map[string]int{
		"one small volume":      1000,
		"exactly one full":      capacity,
		"one byte over":         capacity + 1,
		"several volumes":       5*capacity + 1234,
		"exactly three volumes": 3 * capacity,
	} {
		t.Run(name, func(t *testing.T) {
			data := testPayload(t, size)
			dir := t.TempDir()
			base := writeVolumes(t, dir, data)
			want := (size + capacity - 1) / capacity
			paths, _ := filepath.Glob(base + ".*")
			if len(paths) != want {
				t.Fatalf("%d volumes, want %d", len(paths), want)
			}
			var total int64
			for _, p := range paths {
				info, err := os.Stat(p)
				if err != nil {
					t.Fatal(err)
				}
				if info.Size() > testVolumeSize {
					t.Fatalf("%s is %d bytes, over the volume size", p, info.Size())
				}
				total += info.Size()
			}
			if total != int64(size+want*archive.VolumeOverhead) {
				t.Fatalf("volumes total %d bytes, want data plus %d per volume", total, archive.VolumeOverhead)
			}
			got, err := readVolumes(t, base)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("joined volumes differ: %v", err)
			}
		})
	}
}

func TestFindVolumes(t *testing.T) {
	dir := t.TempDir()
	base := writeVolumes(t, dir, testPayload(t, 3*testVolumeSize))
	for _, p := range []string{VolumePath(base, 1), VolumePath(base, 2), base} {
		if got, ok := FindVolumes(p); !ok || got != base {
			t.Fatalf("FindVolumes(%s) = %q, %v", p, got, ok)
		}
	}
	plain := filepath.Join(dir, "plain.sarc")
	if err := os.WriteFile(plain, []byte("SARC not split"), 0o600); err != nil {
		t.Fatal(err)
	}
	notVolume := filepath.Join(dir, "notes.001")
	if err := os.WriteFile(notVolume, []byte("just a file"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{plain, notVolume, filepath.Join(dir, "absent")} {
		if _, ok := FindVolumes(p); ok {
			t.Fatalf("%s treated as a split archive", p)
		}
	}
}

func TestVolumeSetProblemsNameTheVolume(t *testing.T) {
	data := testPayload(t, 4*testVolumeSize)
	cases := map[string]struct {
		damage  func(t *testing.T, base string)
		index   int
		problem string
	}{
		"missing middle": {func(t *testing.T, base string) { os.Remove(VolumePath(base, 2)) }, 2, "missing"},
		"missing last":   {func(t *testing.T, base string) { os.Remove(VolumePath(base, 5)) }, 5, "missing"},
		"missing first":  {func(t *testing.T, base string) { os.Remove(VolumePath(base, 1)) }, 1, "missing"},
		"truncated": {func(t *testing.T, base string) {
			p := VolumePath(base, 3)
			info, _ := os.Stat(p)
			os.Truncate(p, info.Size()-10)
		}, 3, "truncated"},
		"swapped": {func(t *testing.T, base string) {
			a, b := VolumePath(base, 2), VolumePath(base, 3)
			os.Rename(a, a+".tmp")
			os.Rename(b, a)
			os.Rename(a+".tmp", b)
		}, 2, "out of order"},
		"foreign volume": {func(t *testing.T, base string) {
			other := writeVolumes(t, t.TempDir(), testPayload(t, 4*testVolumeSize))
			copyFile(t, VolumePath(other, 3), VolumePath(base, 3))
		}, 3, "different archive"},
		"not a volume": {func(t *testing.T, base string) {
			os.WriteFile(VolumePath(base, 4), bytes.Repeat([]byte("x"), 100), 0o600)
		}, 4, "not a sarc volume"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			base := writeVolumes(t, t.TempDir(), data)
			c.damage(t, base)
			_, err := readVolumes(t, base)
			requireVolumeError(t, err, c.index, c.problem)
		})
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptedVolumeIsNamedWhileReading(t *testing.T) {
	base := writeVolumes(t, t.TempDir(), testPayload(t, 4*testVolumeSize))
	p := VolumePath(base, 3)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 1 // same size, so only the checksum catches it
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = readVolumes(t, base)
	requireVolumeError(t, err, 3, "corrupted")
}

func TestVolumeStreamReader(t *testing.T) {
	data := testPayload(t, 3*testVolumeSize+77)
	base := writeVolumes(t, t.TempDir(), data)
	var joined bytes.Buffer
	paths, _ := filepath.Glob(base + ".*")
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		joined.Write(b)
	}
	vr := NewVolumeStreamReader(bytes.NewReader(joined.Bytes()))
	got, err := io.ReadAll(vr)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("stream join: %v", err)
	}
	if vr.Volumes() != len(paths) {
		t.Fatalf("Volumes() = %d, want %d", vr.Volumes(), len(paths))
	}

	// Concatenated in the wrong order, the stream names the misplaced volume.
	first, _ := os.ReadFile(paths[0])
	third, _ := os.ReadFile(paths[2])
	_, err = io.ReadAll(NewVolumeStreamReader(bytes.NewReader(append(first, third...))))
	requireVolumeError(t, err, 2, "out of order")
	// Cut short, the stream reports the volume it stopped in.
	_, err = io.ReadAll(NewVolumeStreamReader(bytes.NewReader(joined.Bytes()[:joined.Len()-100])))
	requireVolumeError(t, err, len(paths), "truncated")
}

func TestCreateVolumesRemovesStaleVolumes(t *testing.T) {
	dir := t.TempDir()
	base := writeVolumes(t, dir, testPayload(t, 5*testVolumeSize))
	unrelated := VolumePath(base, 9)
	if err := os.WriteFile(unrelated, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	data := testPayload(t, testVolumeSize/2)
	writeVolumes(t, dir, data)
	paths, _ := filepath.Glob(base + ".00*")
	if len(paths) != 2 || paths[0] != VolumePath(base, 1) || paths[1] != unrelated {
		t.Fatalf("after a shorter archive: %v", paths)
	}
	if got, err := readVolumes(t, base); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("shorter archive: %v", err)
	}
}

func TestCreateVolumesRejectsTinyVolumes(t *testing.T) {
	if _, err := CreateVolumes(filepath.Join(t.TempDir(), "x"), MinVolumeSize-1); err == nil {
		t.Fatal("volume size below the minimum accepted")
	}
}
