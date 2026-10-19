// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/spf13/cobra"
)

func TestParseRecipientsInlineAndFile(t *testing.T) {
	a, _ := age.GenerateX25519Identity()
	b, _ := age.GenerateX25519Identity()
	file := filepath.Join(t.TempDir(), "team.txt")
	content := "# team keys\n\n" + b.Recipient().String() + "\n"
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := parseRecipients([]string{a.Recipient().String(), file})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d recipients, want 2", len(got))
	}
}

func TestParseRecipientsRejectsInvalidInput(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.txt")
	if err := os.WriteFile(bad, []byte("not a key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"age1notavalidkey", bad, filepath.Join(t.TempDir(), "missing.txt")} {
		if _, err := parseRecipients([]string{v}); err == nil {
			t.Fatalf("%q accepted", v)
		}
	}
}

func TestLoadIdentitiesErrorDoesNotEchoSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.key")
	secret := "AGE-SECRET-KEY-1NOTREALBUTSECRETLOOKINGVALUE"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadIdentities([]string{path})
	if err == nil {
		t.Fatal("malformed identity accepted")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error leaks key material: %v", err)
	}
}

func TestReaderOptionsRequireACredential(t *testing.T) {
	flagPassword, flagIdentities = "", nil
	if _, err := readerOptions(); err == nil {
		t.Fatal("accepted no password and no identity")
	}
}

func runKeygenTo(t *testing.T, output string) (string, string, error) {
	t.Helper()
	flagKeygenOutput = output
	var stdout, stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := runKeygen(cmd, nil)
	return stdout.String(), stderr.String(), err
}

func TestKeygenWritesUsableIdentityFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "me.key")
	_, stderr, err := runKeygenTo(t, path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != identityFileMode {
		t.Fatalf("identity file mode %v, want %v", info.Mode().Perm(), os.FileMode(identityFileMode))
	}
	ids, err := loadIdentities([]string{path})
	if err != nil || len(ids) != 1 {
		t.Fatalf("written identity does not parse: %v", err)
	}
	pub := ids[0].(*age.X25519Identity).Recipient().String()
	if !strings.Contains(stderr, pub) {
		t.Fatalf("printed public key %q does not match identity %s", stderr, pub)
	}
}

func TestKeygenNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.key")
	if err := os.WriteFile(path, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runKeygenTo(t, path); err == nil {
		t.Fatal("keygen overwrote an existing file")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "keep me\n" {
		t.Fatalf("existing file changed: %q %v", got, err)
	}
}

func TestKeygenToStdoutMatchesAgeKeygenFormat(t *testing.T) {
	stdout, _, err := runKeygenTo(t, "")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "# created: ") || !strings.HasPrefix(lines[1], "# public key: age1") ||
		!strings.HasPrefix(lines[2], "AGE-SECRET-KEY-1") {
		t.Fatalf("unexpected keygen output format:\n%s", stdout)
	}
	if _, err := age.ParseIdentities(strings.NewReader(stdout)); err != nil {
		t.Fatalf("stdout identity does not parse: %v", err)
	}
}
