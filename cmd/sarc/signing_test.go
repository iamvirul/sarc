// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	sarcio "github.com/iamvirul/sarc/io"
)

func newEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, sshPub
}

func authorizedLine(key ssh.PublicKey, comment string) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " " + comment
}

func TestParseSignersFormats(t *testing.T) {
	_, _, a := newEd25519(t)
	_, _, b := newEd25519(t)
	cPub, _, c := newEd25519(t)
	authorized := writeTestFile(t, "keys", []byte("# team\n"+authorizedLine(a, "alice")+"\n\n"+authorizedLine(b, "bob")+"\n"))
	allowed := writeTestFile(t, "allowed_signers", []byte("release@example.com "+authorizedLine(c, "ci")+"\n"))
	der, err := x509.MarshalPKIXPublicKey(cPub)
	if err != nil {
		t.Fatal(err)
	}
	pemFile := writeTestFile(t, "c.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	got, err := parseSigners([]string{authorizedLine(a, "inline"), authorized, allowed, pemFile})
	if err != nil {
		t.Fatal(err)
	}
	want := []ssh.PublicKey{a, a, b, c, c}
	if len(got) != len(want) {
		t.Fatalf("got %d signers, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i].key.Marshal(), want[i].Marshal()) {
			t.Fatalf("signer %d differs", i)
		}
	}
	if got[1].label != "alice" || got[0].label != "inline" {
		t.Fatalf("labels %q %q", got[0].label, got[1].label)
	}
}

func TestParseSignersRejectsBadInput(t *testing.T) {
	_, priv, _ := newEd25519(t)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{
		"inline garbage": "ssh-ed25519 notbase64",
		"missing file":   filepath.Join(t.TempDir(), "missing.pub"),
		"empty file":     writeTestFile(t, "empty.pub", []byte("# nothing\n")),
		"garbage file":   writeTestFile(t, "garbage.pub", []byte("hello world\n")),
		"private key":    writeTestFile(t, "id", pem.EncodeToMemory(block)),
	} {
		if _, err := parseSigners([]string{v}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestLoadSignerFormats(t *testing.T) {
	_, edPriv, edPub := newEd25519(t)
	openssh, err := ssh.MarshalPrivateKey(edPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		pem  []byte
		want string
	}{
		"openssh ed25519": {pem.EncodeToMemory(openssh), ssh.KeyAlgoED25519},
		"pkcs8 ed25519":   {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), ssh.KeyAlgoED25519},
		"pkcs1 rsa":       {pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), ssh.KeyAlgoRSA},
	} {
		signer, err := loadSigner(writeTestFile(t, "key", c.pem))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if signer.PublicKey().Type() != c.want {
			t.Fatalf("%s: key type %s", name, signer.PublicKey().Type())
		}
		if name != "pkcs1 rsa" && !bytes.Equal(signer.PublicKey().Marshal(), edPub.Marshal()) {
			t.Fatalf("%s: wrong public key", name)
		}
	}
	secret := "-----BEGIN OPENSSH PRIVATE KEY-----\nTOTALLYSECRETBYTES\n-----END OPENSSH PRIVATE KEY-----\n"
	_, err = loadSigner(writeTestFile(t, "bad", []byte(secret)))
	if err == nil || strings.Contains(err.Error(), "TOTALLYSECRET") {
		t.Fatalf("bad key: %v", err)
	}
}

func TestWriteSigningKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.key")
	pub, err := writeSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != identityFileMode {
		t.Fatalf("private key mode: %v %v", info.Mode().Perm(), err)
	}
	signer, err := loadSigner(path)
	if err != nil || !bytes.Equal(signer.PublicKey().Marshal(), pub.Marshal()) {
		t.Fatalf("private key does not load as the returned key: %v", err)
	}
	signers, err := parseSigners([]string{path + ".pub"})
	if err != nil || len(signers) != 1 || !bytes.Equal(signers[0].key.Marshal(), pub.Marshal()) || signers[0].label != signingKeyComment {
		t.Fatalf("public key file: %+v %v", signers, err)
	}
	if _, err := writeSigningKey(path); err == nil {
		t.Fatal("signing key overwritten")
	}
	other := filepath.Join(t.TempDir(), "other.key")
	if err := os.WriteFile(other+".pub", []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := writeSigningKey(other); err == nil {
		t.Fatal("existing .pub overwritten")
	}
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Fatal("private key left behind after refusing the .pub")
	}
}

func TestReportSignature(t *testing.T) {
	_, _, alice := newEd25519(t)
	_, _, bob := newEd25519(t)
	trusted := []trustedSigner{{key: alice, label: "alice"}}
	cases := map[string]struct {
		report  sarcio.VerifyReport
		signers []trustedSigner
		fail    bool
		say     string
	}{
		"unsigned, none required": {sarcio.VerifyReport{}, nil, false, ""},
		"unsigned, required":      {sarcio.VerifyReport{}, trusted, true, "MISSING"},
		"invalid":                 {sarcio.VerifyReport{Signed: true, SignatureErr: errors.New("bad")}, nil, true, "INVALID"},
		"valid, untrusted check":  {sarcio.VerifyReport{Signed: true, Signer: alice}, nil, false, "pass --signer"},
		"valid, trusted":          {sarcio.VerifyReport{Signed: true, Signer: alice}, trusted, false, "VALID: signed by"},
		"valid, other signer":     {sarcio.VerifyReport{Signed: true, Signer: bob}, trusted, true, "UNTRUSTED"},
	}
	for name, c := range cases {
		var out bytes.Buffer
		err := reportSignature(&out, c.report, c.signers)
		if (err != nil) != c.fail || !strings.Contains(out.String(), c.say) {
			t.Errorf("%s: err %v, output %q", name, err, out.String())
		}
	}
}
