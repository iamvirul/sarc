// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/iamvirul/sarc/crypto"
)

func newSigner(t *testing.T, kind string) ssh.Signer {
	t.Helper()
	var key any
	var err error
	switch kind {
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa1024":
		key, err = rsa.GenerateKey(rand.Reader, 1024)
	}
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestSignatureRoundtripPerKeyType(t *testing.T) {
	message := []byte("archive checksum")
	for _, kind := range []string{"ed25519", "ecdsa", "rsa"} {
		t.Run(kind, func(t *testing.T) {
			signer := newSigner(t, kind)
			blob, err := crypto.SignMessage(signer, message)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := crypto.VerifyMessage(blob, message)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
				t.Fatal("verified key differs from the signer's")
			}
			if _, err := crypto.VerifyMessage(blob, []byte("other checksum")); !errors.Is(err, crypto.ErrBadSignature) {
				t.Fatalf("signature verified over a different message: %v", err)
			}
		})
	}
}

func TestSignatureRejectsWeakRSA(t *testing.T) {
	if _, err := crypto.SignMessage(newSigner(t, "rsa1024"), []byte("m")); err == nil {
		t.Fatal("1024-bit RSA key signed")
	}
}

// sshString and rebuild help forge variants of a valid blob.
func sshString(s []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
}

func rebuild(pubKey, namespace, hashAlgo, sig []byte) []byte {
	b := append([]byte("SSHSIG"), 0, 0, 0, 1)
	for _, f := range [][]byte{pubKey, namespace, nil, hashAlgo, sig} {
		b = append(b, sshString(f)...)
	}
	return b
}

func TestSignatureRejectsMalformedAndMismatchedBlobs(t *testing.T) {
	signer := newSigner(t, "ed25519")
	message := []byte("checksum")
	blob, err := crypto.SignMessage(signer, message)
	if err != nil {
		t.Fatal(err)
	}
	other := newSigner(t, "ed25519")
	otherSig, err := other.Sign(rand.Reader, []byte("unrelated"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":          nil,
		"bad magic":      append([]byte("XXXXXX"), blob[6:]...),
		"truncated":      blob[:len(blob)-5],
		"trailing bytes": append(bytes.Clone(blob), 0),
		"flipped byte":   func() []byte { b := bytes.Clone(blob); b[len(b)-3] ^= 1; return b }(),
		"wrong namespace": rebuild(signer.PublicKey().Marshal(), []byte("file"), []byte("sha512"),
			ssh.Marshal(otherSig)),
		"wrong key for signature": rebuild(other.PublicKey().Marshal(), []byte(crypto.SignatureNamespace), []byte("sha512"),
			blob[len(blob)-len(ssh.Marshal(otherSig)):]),
	}
	for name, b := range cases {
		if _, err := crypto.VerifyMessage(b, message); !errors.Is(err, crypto.ErrBadSignature) {
			t.Errorf("%s: want ErrBadSignature, got %v", name, err)
		}
	}
}

func TestArmorRoundtrip(t *testing.T) {
	blob, err := crypto.SignMessage(newSigner(t, "ed25519"), []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	armored := crypto.ArmorSignature(blob)
	if !bytes.HasPrefix(armored, []byte("-----BEGIN SSH SIGNATURE-----\n")) {
		t.Fatalf("armor header missing:\n%s", armored)
	}
	got, err := crypto.DearmorSignature(armored)
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("dearmor: %v", err)
	}
	if _, err := crypto.DearmorSignature([]byte("not armored")); err == nil {
		t.Fatal("garbage dearmored")
	}
}

// writeOpenSSHKey writes signer's private key for ssh-keygen and returns its path.
func writeOpenSSHKey(t *testing.T, dir string, key ed25519.PrivateKey) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(key, "sarc test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSignatureInteropWithSSHKeygen checks both directions against OpenSSH: ssh-keygen
// accepts sarc's signatures, and sarc accepts ssh-keygen's.
func TestSignatureInteropWithSSHKeygen(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeOpenSSHKey(t, dir, priv)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("0123456789abcdef0123456789abcdef")
	msgPath := filepath.Join(dir, "checksum")
	if err := os.WriteFile(msgPath, message, 0o600); err != nil {
		t.Fatal(err)
	}

	blob, err := crypto.SignMessage(signer, message)
	if err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(dir, "sarc.sig")
	if err := os.WriteFile(sigPath, crypto.ArmorSignature(blob), 0o600); err != nil {
		t.Fatal(err)
	}
	check := exec.Command("ssh-keygen", "-Y", "check-novalidate", "-n", crypto.SignatureNamespace, "-s", sigPath)
	check.Stdin = bytes.NewReader(message)
	if out, err := check.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen rejected a sarc signature: %v\n%s", err, out)
	}

	sign := exec.Command("ssh-keygen", "-Y", "sign", "-n", crypto.SignatureNamespace, "-O", "hashalg=sha512", "-f", keyPath, msgPath)
	if out, err := sign.CombinedOutput(); err != nil {
		if strings.Contains(string(out), "hashalg") {
			t.Skip("ssh-keygen too old for -O hashalg")
		}
		t.Fatalf("ssh-keygen sign: %v\n%s", err, out)
	}
	armored, err := os.ReadFile(msgPath + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := crypto.DearmorSignature(armored)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := crypto.VerifyMessage(theirs, message)
	if err != nil {
		t.Fatalf("sarc rejected an ssh-keygen signature: %v", err)
	}
	if !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
		t.Fatal("ssh-keygen signature verified under a different key")
	}
}
