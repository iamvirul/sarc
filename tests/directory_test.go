// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	sarcio "github.com/iamvirul/sarc/io"
)

const directoryTestPassword = "directory-test-pass"

// writeTestTree creates a nested tree under root/data and returns its files by
// slash-separated name relative to root.
func writeTestTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{
		"data/readme.md":            compressibleText(4 * 1024),
		"data/src/main.go":          compressibleText(20 * 1024),
		"data/src/util/strings.go":  compressibleText(9 * 1024),
		"data/assets/photo.raw":     randomContent(t, 5*1024*1024),
		"data/assets/empty.txt":     {},
		"data/.config/settings.ini": []byte("key=value\n"),
	}
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

// readTree returns every regular file under root by slash-separated relative name.
func readTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	got := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(p)
		got[filepath.ToSlash(rel)] = content
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func requireSameTree(t *testing.T, got, want map[string][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d files, want %d: %v", len(got), len(want), keys(got))
	}
	for name, content := range want {
		if !bytes.Equal(got[name], content) {
			t.Fatalf("%s: missing or different", name)
		}
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDirectoryTreeRoundtrip(t *testing.T) {
	root := t.TempDir()
	want := writeTestTree(t, root)
	dataDir := filepath.Join(root, "data")

	archivers := map[string]func(*bytes.Buffer) error{
		"concurrent": func(buf *bytes.Buffer) error {
			ca, err := sarcio.NewConcurrentArchiver(buf, directoryTestPassword, 4, nil)
			if err != nil {
				return err
			}
			return ca.Archive([]string{dataDir})
		},
		"concurrent solid": func(buf *bytes.Buffer) error {
			opts := sarcio.DefaultCompressionOptions()
			opts.Solid = true
			ca, err := sarcio.NewConcurrentArchiver(buf, directoryTestPassword, 4, nil, sarcio.WithCompression(opts))
			if err != nil {
				return err
			}
			return ca.Archive([]string{dataDir})
		},
		"streaming": func(buf *bytes.Buffer) error {
			sa, err := sarcio.NewStreamingArchiver(buf, directoryTestPassword, nil)
			if err != nil {
				return err
			}
			if err := sa.AddFile(dataDir); err != nil {
				return err
			}
			return sa.Finalize(len(want), 0)
		},
	}
	for name, archiveTree := range archivers {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := archiveTree(&buf); err != nil {
				t.Fatal(err)
			}
			out := t.TempDir()
			results, err := sarcio.NewSafeExtractor(bytes.NewReader(buf.Bytes()), directoryTestPassword, nil).Extract(out)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range results {
				if !r.OK {
					t.Fatalf("%s failed: %v", r.Filename, r.Err)
				}
			}
			requireSameTree(t, readTree(t, out), want)
		})
	}
}
