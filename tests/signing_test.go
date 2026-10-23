// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package tests_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
	sarcio "github.com/iamvirul/sarc/io"
)

const signingTestPassword = "signing-test-pass"

func newSSHSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func requireSignedBy(t *testing.T, data []byte, signer ssh.Signer) {
	t.Helper()
	rep, err := sarcio.VerifyArchive(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.ChecksumOK || !rep.Signed || rep.SignatureErr != nil || !bytes.Equal(rep.Signer.Marshal(), signer.PublicKey().Marshal()) {
		t.Fatalf("want a valid signature by the signer: %+v", rep)
	}
}

func requireUnsigned(t *testing.T, data []byte) {
	t.Helper()
	rep, err := sarcio.VerifyArchive(bytes.NewReader(data))
	if err != nil || !rep.ChecksumOK || rep.Signed {
		t.Fatalf("want an intact unsigned archive: %+v %v", rep, err)
	}
}

func TestArchiversSignWithSigner(t *testing.T) {
	signer := newSSHSigner(t)
	root := t.TempDir()
	want := writeTestTree(t, root)
	dataDir := filepath.Join(root, "data")
	for name, build := range map[string]func(*bytes.Buffer) error{
		"concurrent": func(buf *bytes.Buffer) error {
			ca, err := sarcio.NewConcurrentArchiver(buf, signingTestPassword, 4, nil, sarcio.WithSigner(signer))
			if err != nil {
				return err
			}
			return ca.Archive([]string{dataDir})
		},
		"streaming": func(buf *bytes.Buffer) error {
			sa, err := sarcio.NewStreamingArchiver(buf, signingTestPassword, nil, sarcio.WithSigner(signer))
			if err != nil {
				return err
			}
			if err := sa.AddFile(dataDir); err != nil {
				return err
			}
			return sa.Finalize(len(want), 0)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := build(&buf); err != nil {
				t.Fatal(err)
			}
			requireSignedBy(t, buf.Bytes(), signer)
			// Extraction, even streaming, stops at the end marker and ignores the signature.
			out := t.TempDir()
			if _, err := sarcio.NewSafeExtractor(bytes.NewReader(buf.Bytes()), signingTestPassword, nil).Extract(out); err != nil {
				t.Fatal(err)
			}
			requireSameTree(t, readTree(t, out), want)
		})
	}
}

func writeArchiveFile(t *testing.T, opts ...sarcio.ArchiverOption) (string, []byte) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "doc.txt")
	if err := os.WriteFile(src, compressibleText(64*1024), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	ca, err := sarcio.NewConcurrentArchiver(&buf, signingTestPassword, 2, nil, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Archive([]string{src}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "a.sarc")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, buf.Bytes()
}

func TestSignArchiveFileSignsAndReplaces(t *testing.T) {
	alice := newSSHSigner(t)
	bob := newSSHSigner(t)
	path, unsigned := writeArchiveFile(t)
	if err := sarcio.SignArchiveFile(path, alice); err != nil {
		t.Fatal(err)
	}
	signed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed[:len(unsigned)], unsigned) {
		t.Fatal("signing changed the archive itself")
	}
	requireSignedBy(t, signed, alice)

	if err := sarcio.SignArchiveFile(path, bob); err != nil {
		t.Fatal(err)
	}
	resigned, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	requireSignedBy(t, resigned, bob)
	if len(resigned) != len(signed) {
		t.Fatalf("re-signing left %d bytes, want %d (one signature block)", len(resigned), len(signed))
	}
}

func TestSignArchiveFileRefusesCorruptedArchives(t *testing.T) {
	signer := newSSHSigner(t)
	path, data := writeArchiveFile(t)
	corrupt := bytes.Clone(data)
	corrupt[len(corrupt)/2] ^= 1
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	var ae *sarcio.ArchiveError
	if err := sarcio.SignArchiveFile(path, signer); !errors.As(err, &ae) || ae.Code != sarcio.ErrCodeIntegrityFail {
		t.Fatalf("want %s, got %v", sarcio.ErrCodeIntegrityFail, err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, corrupt) {
		t.Fatal("refused signing still modified the file")
	}
	notSarc := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(notSarc, bytes.Repeat([]byte("x"), 500), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sarcio.SignArchiveFile(notSarc, signer); err == nil {
		t.Fatal("signed a file that is not an archive")
	}
}

func incrementalWithSigner(t *testing.T, path string, signer ssh.Signer, inputs ...string) sarcio.IncrementalResult {
	t.Helper()
	opts := sarcio.IncrementalOptions{Password: signingTestPassword, UnlockPassword: signingTestPassword}
	if signer != nil {
		opts.Archiver = []sarcio.ArchiverOption{sarcio.WithSigner(signer)}
	}
	res, err := sarcio.ArchiveIncremental(path, inputs, opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestSignedIncrementalArchiveLifecycle(t *testing.T) {
	signer := newSSHSigner(t)
	root := t.TempDir()
	writeFile(t, root, "data/a.txt", []byte("first"))
	dataDir := filepath.Join(root, "data")
	path := filepath.Join(t.TempDir(), "inc.sarc")
	read := func() []byte {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	if res := incrementalWithSigner(t, path, signer, dataDir); !res.Signed {
		t.Fatalf("created archive not signed: %+v", res)
	}
	requireSignedBy(t, read(), signer)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := f.Stat()
	out := t.TempDir()
	if _, err := sarcio.NewSafeExtractor(f, signingTestPassword, nil, sarcio.WithRandomAccess(f, info.Size())).Extract(out); err != nil {
		t.Fatalf("restore a signed incremental archive: %v", err)
	}
	f.Close()

	// No change: the archive, signature included, is left byte for byte.
	before := read()
	if res := incrementalWithSigner(t, path, signer, dataDir); res.Signed || res.AppendedBytes != 0 {
		t.Fatalf("unchanged signed run: %+v", res)
	}
	if !bytes.Equal(read(), before) {
		t.Fatal("unchanged run touched a validly signed archive")
	}

	// A change with the signer re-signs; without it the stale signature is removed.
	writeFile(t, root, "data/a.txt", []byte("second"))
	if res := incrementalWithSigner(t, path, signer, dataDir); !res.Signed {
		t.Fatalf("update not re-signed: %+v", res)
	}
	requireSignedBy(t, read(), signer)
	writeFile(t, root, "data/a.txt", []byte("third"))
	if res := incrementalWithSigner(t, path, nil, dataDir); !res.SignatureRemoved {
		t.Fatalf("stale signature not reported removed: %+v", res)
	}
	requireUnsigned(t, read())

	// Signing an unchanged, unsigned archive verifies and signs it.
	if res := incrementalWithSigner(t, path, signer, dataDir); !res.Signed || res.AppendedBytes != 0 {
		t.Fatalf("signing an unchanged archive: %+v", res)
	}
	requireSignedBy(t, read(), signer)
	got := restoreIncrementalWith(t, path, signingTestPassword)
	if string(got["data/a.txt"]) != "third" {
		t.Fatalf("restored %q", got["data/a.txt"])
	}
}

// TestFailedIncrementalUpdateKeepsSignature makes every changed file unreadable, so the
// update writes nothing, and checks the archive and its signature are exactly restored.
func TestFailedIncrementalUpdateKeepsSignature(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read unreadable files")
	}
	signer := newSSHSigner(t)
	root := t.TempDir()
	writeFile(t, root, "data/a.txt", []byte("readable"))
	dataDir := filepath.Join(root, "data")
	path := filepath.Join(t.TempDir(), "inc.sarc")
	incrementalWithSigner(t, path, signer, dataDir)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(root, "data", "a.txt")
	writeFile(t, root, "data/a.txt", []byte("changed but unreadable"))
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o644) })
	res := incrementalWithSigner(t, path, nil, dataDir)
	if res.Failed != 1 || res.SignatureRemoved {
		t.Fatalf("failed update: %+v", res)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("an update that recorded nothing changed the signed archive")
	}
}

func restoreIncrementalWith(t *testing.T, path, password string) map[string][]byte {
	t.Helper()
	out := t.TempDir()
	if _, err := openIncremental(t, path, password).Extract(out); err != nil {
		t.Fatal(err)
	}
	return readTree(t, out)
}

// TestArchiveSignatureVerifiesWithSSHKeygen checks the documented manual procedure: the
// signature block, armored, verifies with ssh-keygen over the footer checksum.
func TestArchiveSignatureVerifiesWithSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	signer := newSSHSigner(t)
	_, data := writeArchiveFile(t, sarcio.WithSigner(signer))
	sigLen, ok := archive.ParseSignatureTrailer(data[len(data)-archive.SignatureTrailerSize:])
	if !ok {
		t.Fatal("no signature trailer")
	}
	proper := data[:len(data)-archive.SignatureTrailerSize-sigLen]
	sig := data[len(proper) : len(proper)+sigLen]
	checksum := proper[len(proper)-archive.FooterSize:][:archive.HMACSize]

	dir := t.TempDir()
	sigPath := filepath.Join(dir, "archive.sig")
	if err := os.WriteFile(sigPath, crypto.ArmorSignature(sig), 0o600); err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(dir, "allowed_signers")
	line := "release@example " + string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + "\n"
	if err := os.WriteFile(allowed, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "release@example",
		"-n", crypto.SignatureNamespace, "-s", sigPath)
	cmd.Stdin = bytes.NewReader(checksum)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen rejected the archive signature: %v\n%s", err, out)
	}
}
