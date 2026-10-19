// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// buildTestPlugin builds testdata/age-plugin-sarctest into its own directory, returns
// that directory (to put on PATH), and a fresh identity file with its recipient.
func buildTestPlugin(t *testing.T) (pluginDir, identityFile, recipient string) {
	t.Helper()
	pluginDir = t.TempDir()
	bin := filepath.Join(pluginDir, "age-plugin-sarctest")
	if out, err := exec.Command("go", "build", "-o", bin, "./testdata/age-plugin-sarctest").CombinedOutput(); err != nil {
		t.Fatalf("build test plugin: %v\n%s", err, out)
	}
	generated, err := exec.Command(bin, "-generate").Output()
	if err != nil {
		t.Fatalf("generate plugin identity: %v", err)
	}
	recipient = regexp.MustCompile(`age1sarctest1[0-9a-z]+`).FindString(string(generated))
	if recipient == "" {
		t.Fatalf("no recipient in plugin output:\n%s", generated)
	}
	identityFile = filepath.Join(t.TempDir(), "token.id")
	if err := os.WriteFile(identityFile, generated, 0o600); err != nil {
		t.Fatal(err)
	}
	return pluginDir, identityFile, recipient
}

// runWithPath runs the sarc binary with PATH set to path, feeding stdin.
func runWithPath(t *testing.T, path string, stdin []byte, args ...string) (stdout, stderr []byte, err error) {
	t.Helper()
	cmd := exec.Command(sarcBinary(t), args...)
	cmd.Env = append(os.Environ(), "PATH="+path)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	return out.Bytes(), errOut.Bytes(), err
}

// TestHardwareTokenPluginRoundtrip archives to a plugin recipient (as for
// age1yubikey1...) through stdout and extracts with the plugin identity from stdin. The
// plugin's messages must reach stderr only, never the archive stream.
func TestHardwareTokenPluginRoundtrip(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the sarc binary and a test plugin")
	}
	pluginDir, identity, recipient := buildTestPlugin(t)
	path := pluginDir + string(os.PathListSeparator) + os.Getenv("PATH")
	src := filepath.Join(t.TempDir(), "secret.txt")
	want := compressibleText(30 * 1024)
	if err := os.WriteFile(src, want, 0o644); err != nil {
		t.Fatal(err)
	}

	archived, stderr, err := runWithPath(t, path, nil, "archive", "-r", recipient, "-o", "-", src)
	if err != nil {
		t.Fatalf("archive: %v\n%s", err, stderr)
	}
	if !bytes.HasPrefix(archived, []byte("SARC")) {
		t.Fatalf("stdout is not an archive; plugin output may have leaked into it: %q", archived[:min(len(archived), 64)])
	}
	if !strings.Contains(string(stderr), "sarctest token wrapping") {
		t.Fatalf("plugin message missing from stderr:\n%s", stderr)
	}

	outDir := filepath.Join(t.TempDir(), "out")
	out, stderr, err := runWithPath(t, path, archived, "extract", "-i", identity, "-a", "-", "-o", outDir)
	if err != nil {
		t.Fatalf("extract: %v\n%s%s", err, out, stderr)
	}
	if !strings.Contains(string(stderr), "touch your sarctest token") {
		t.Fatalf("plugin prompt missing from stderr:\n%s", stderr)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "secret.txt"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("content mismatch after plugin roundtrip (%v)", err)
	}

	// Without the plugin installed the identity cannot be used, and nothing is written.
	missingDir := filepath.Join(t.TempDir(), "out")
	out, stderr, err = runWithPath(t, filepath.Dir(sarcBinary(t)), archived, "extract", "-i", identity, "-a", "-", "-o", missingDir)
	if err == nil || !strings.Contains(string(out)+string(stderr), "plugin not found") {
		t.Fatalf("missing plugin not reported: %v\n%s%s", err, out, stderr)
	}
	if _, statErr := os.Stat(missingDir); !os.IsNotExist(statErr) {
		t.Fatalf("output written without the plugin: %v", statErr)
	}
}

// TestArchiveForIdentityUsesItsPublicKey archives with --identity pointing at the
// plugin identity, so only the identity's public half is needed to archive.
func TestArchiveForIdentityUsesItsPublicKey(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the sarc binary and a test plugin")
	}
	pluginDir, identity, _ := buildTestPlugin(t)
	path := pluginDir + string(os.PathListSeparator) + os.Getenv("PATH")
	src := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(src, []byte("for my token\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	archived, stderr, err := runWithPath(t, path, nil, "archive", "-i", identity, "-o", "-", src)
	if err != nil {
		t.Fatalf("archive: %v\n%s", err, stderr)
	}
	out, stderr, err := runWithPath(t, path, archived, "list", "-i", identity, "-a", "-")
	if err != nil || !strings.Contains(string(out), "notes.txt") {
		t.Fatalf("list: %v\n%s%s", err, out, stderr)
	}
}
