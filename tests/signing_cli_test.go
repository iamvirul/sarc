// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSigningCLI runs the issue's workflow through the real binary and checks verify
// --signer exits 0 only for a valid signature by a trusted key.
func TestSigningCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the sarc binary")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "signing.key")
	if out, err := runSarc(t, nil, "keygen", "--signing", "-o", key); err != nil || !strings.Contains(out, "SHA256:") {
		t.Fatalf("keygen --signing: %v\n%s", err, out)
	}
	src := filepath.Join(dir, "release.txt")
	if err := os.WriteFile(src, []byte("release notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(dir, "release.sarc")
	if out, err := runSarc(t, nil, "archive", "-p", signingTestPassword, "--sign", key, "-o", signed, src); err != nil ||
		!strings.Contains(out, "signed with SHA256:") {
		t.Fatalf("archive --sign: %v\n%s", err, out)
	}
	verify := func(archivePath string, signers ...string) (string, error) {
		t.Helper()
		args := []string{"verify", "-a", archivePath}
		for _, s := range signers {
			args = append(args, "--signer", s)
		}
		return runSarc(t, nil, args...)
	}
	if out, err := verify(signed, key+".pub"); err != nil || !strings.Contains(out, "signature VALID") || !strings.Contains(out, "PASSED") {
		t.Fatalf("valid signature: %v\n%s", err, out)
	}

	otherKey := filepath.Join(dir, "other.key")
	if _, err := runSarc(t, nil, "keygen", "--signing", "-o", otherKey); err != nil {
		t.Fatal(err)
	}
	if out, err := verify(signed, otherKey+".pub"); err == nil || !strings.Contains(out, "UNTRUSTED") {
		t.Fatalf("wrong signer: %v\n%s", err, out)
	}
	if out, err := verify(signed, otherKey+".pub", key+".pub"); err != nil {
		t.Fatalf("any trusted signer should do: %v\n%s", err, out)
	}

	unsigned := filepath.Join(dir, "plain.sarc")
	if out, err := runSarc(t, nil, "archive", "-p", signingTestPassword, "-o", unsigned, src); err != nil {
		t.Fatalf("archive: %v\n%s", err, out)
	}
	if out, err := verify(unsigned, key+".pub"); err == nil || !strings.Contains(out, "MISSING") {
		t.Fatalf("missing signature: %v\n%s", err, out)
	}
	if out, err := verify(unsigned); err != nil {
		t.Fatalf("unsigned archives still verify: %v\n%s", err, out)
	}

	// sign signs an existing archive in place, here with a key from ssh-keygen.
	signingKey := key
	if _, err := exec.LookPath("ssh-keygen"); err == nil {
		signingKey = filepath.Join(dir, "id_ed25519")
		if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "ops@example", "-f", signingKey).CombinedOutput(); err != nil {
			t.Fatalf("ssh-keygen: %v\n%s", err, out)
		}
	}
	if out, err := runSarc(t, nil, "sign", "-s", signingKey, "-a", unsigned); err != nil {
		t.Fatalf("sign: %v\n%s", err, out)
	}
	if out, err := verify(unsigned, signingKey+".pub"); err != nil || !strings.Contains(out, "signature VALID") {
		t.Fatalf("after sign: %v\n%s", err, out)
	}

	data, err := os.ReadFile(signed)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := runSarc(t, data, "verify", "-a", "-", "--signer", strings.TrimSpace(string(pub))); err != nil {
		t.Fatalf("verify from stdin with an inline key: %v\n%s", err, out)
	}
	tampered := append([]byte{}, data...)
	tampered[len(tampered)/3] ^= 1
	if out, err := runSarc(t, tampered, "verify", "-a", "-", "--signer", key+".pub"); err == nil || !strings.Contains(out, "INVALID") {
		t.Fatalf("tampered archive: %v\n%s", err, out)
	}
	if out, err := runSarc(t, nil, "extract", "-p", signingTestPassword, "-a", signed, "-o", filepath.Join(dir, "out")); err != nil {
		t.Fatalf("extract a signed archive: %v\n%s", err, out)
	}
}
