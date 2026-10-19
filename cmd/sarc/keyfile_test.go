// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/iamvirul/sarc/crypto"
	sarcio "github.com/iamvirul/sarc/io"
)

const keyFileTestPassword = "second-factor"

// resetCredentialFlags clears the credential flags now and after the test.
func resetCredentialFlags(t *testing.T) {
	t.Helper()
	clear := func() { flagPassword, flagKeyFiles, flagRecipients, flagIdentities = "", nil, nil, nil }
	clear()
	t.Cleanup(clear)
}

func writeTestFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// newSSHKey returns an ed25519 SSH private key in OpenSSH PEM form (passphrase-protected
// when passphrase is non-empty) and its authorized_keys line.
func newSSHKey(t *testing.T, passphrase string) ([]byte, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// archiveAndOpen writes an archive with the current credential flags and reports
// whether it opens with password (empty for none) and keys.
func archiveAndOpen(t *testing.T, password string, keys ...[]byte) bool {
	t.Helper()
	archivePassword, opts, err := archiveCredentials()
	if err != nil {
		t.Fatal(err)
	}
	src := writeTestFile(t, "data.txt", []byte("key file test data\n"))
	var buf bytes.Buffer
	sa, err := sarcio.NewStreamingArchiver(&buf, archivePassword, nil, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.AddFile(src); err != nil {
		t.Fatal(err)
	}
	if err := sa.Finalize(1, 0); err != nil {
		t.Fatal(err)
	}
	_, err = sarcio.NewSafeExtractor(bytes.NewReader(buf.Bytes()), password, nil, sarcio.WithKeyFiles(keys...)).List()
	return err == nil
}

func TestArchiveCredentialsKeyFileAlone(t *testing.T) {
	resetCredentialFlags(t)
	key := randomBytes(t, crypto.MinKeyFileSize)
	flagKeyFiles = []string{writeTestFile(t, "k.key", key)}
	if !archiveAndOpen(t, "", key) {
		t.Fatal("key file does not open its archive")
	}
	if archiveAndOpen(t, "", randomBytes(t, crypto.MinKeyFileSize)) {
		t.Fatal("another key file opened the archive")
	}
}

func TestArchiveCredentialsBindPasswordToKeyFile(t *testing.T) {
	resetCredentialFlags(t)
	key := randomBytes(t, 64)
	flagPassword = keyFileTestPassword
	flagKeyFiles = []string{writeTestFile(t, "k.key", key)}
	if !archiveAndOpen(t, keyFileTestPassword, key) {
		t.Fatal("key file and password do not open the archive")
	}
	if archiveAndOpen(t, keyFileTestPassword) {
		t.Fatal("password alone opened a key file and password archive")
	}
	if archiveAndOpen(t, "", key) {
		t.Fatal("key file alone opened a key file and password archive")
	}
}

func TestArchiveCredentialsValidation(t *testing.T) {
	for name, set := range map[string]func(t *testing.T){
		"no credential":  func(t *testing.T) {},
		"short password": func(t *testing.T) { flagPassword = "short" },
		"short key file": func(t *testing.T) {
			flagKeyFiles = []string{writeTestFile(t, "k.key", randomBytes(t, crypto.MinKeyFileSize-1))}
		},
		"too many key files": func(t *testing.T) {
			path := writeTestFile(t, "k.key", randomBytes(t, 32))
			for range 9 {
				flagKeyFiles = append(flagKeyFiles, path)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			resetCredentialFlags(t)
			set(t)
			if _, _, err := archiveCredentials(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestReadKeyFilesEnforcesSize(t *testing.T) {
	ok := writeTestFile(t, "ok.key", randomBytes(t, crypto.MinKeyFileSize))
	keys, err := readKeyFiles([]string{ok})
	if err != nil || len(keys) != 1 || len(keys[0]) != crypto.MinKeyFileSize {
		t.Fatalf("valid key file: %v", err)
	}
	for name, path := range map[string]string{
		"empty":    writeTestFile(t, "empty.key", nil),
		"short":    writeTestFile(t, "short.key", randomBytes(t, crypto.MinKeyFileSize-1)),
		"too long": writeTestFile(t, "long.key", make([]byte, crypto.MaxKeyFileSize+1)),
		"missing":  filepath.Join(t.TempDir(), "missing.key"),
	} {
		if _, err := readKeyFiles([]string{path}); err == nil {
			t.Fatalf("%s key file accepted", name)
		}
	}
}

func TestParseRecipientsSSHKeys(t *testing.T) {
	_, edPub := newSSHKey(t, "")
	_, filePub := newSSHKey(t, "")
	pubFile := writeTestFile(t, "id.pub", []byte(filePub+"\n"))
	got, err := parseRecipients([]string{edPub, pubFile})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d recipients, want 2", len(got))
	}
	for _, r := range got {
		if _, ok := r.(*agessh.Ed25519Recipient); !ok {
			t.Fatalf("recipient type %T, want *agessh.Ed25519Recipient", r)
		}
	}
}

func TestParseRecipientsPluginAndPostQuantum(t *testing.T) {
	pq, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pluginRecipient := plugin.EncodeRecipient("yubikey", randomBytes(t, 33))
	got, err := parseRecipients([]string{pq.Recipient().String(), pluginRecipient})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[0].(*age.HybridRecipient); !ok {
		t.Fatalf("recipient type %T, want *age.HybridRecipient", got[0])
	}
	if p, ok := got[1].(*plugin.Recipient); !ok || p.Name() != "yubikey" {
		t.Fatalf("recipient %T, want yubikey *plugin.Recipient", got[1])
	}
}

func TestRecipientsFileRejectsPrivateKeysWithoutEchoingThem(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	path := writeTestFile(t, "oops.txt", []byte(id.String()+"\n"))
	_, err := parseRecipients([]string{path})
	if err == nil {
		t.Fatal("private key accepted as a recipient")
	}
	if strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadIdentitiesSSHKeys(t *testing.T) {
	plain, plainPub := newSSHKey(t, "")
	encrypted, encryptedPub := newSSHKey(t, "ssh-passphrase")
	ids, err := loadIdentities([]string{writeTestFile(t, "id_plain", plain), writeTestFile(t, "id_enc", encrypted)})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ids[0].(*agessh.Ed25519Identity); !ok {
		t.Fatalf("identity type %T, want *agessh.Ed25519Identity", ids[0])
	}
	if _, ok := ids[1].(*agessh.EncryptedSSHIdentity); !ok {
		t.Fatalf("identity type %T, want *agessh.EncryptedSSHIdentity", ids[1])
	}
	// Archiving for an identity needs only its public key, never the passphrase.
	recipients, err := recipientsForIdentities(ids)
	if err != nil {
		t.Fatal(err)
	}
	want, err := parseRecipients([]string{plainPub, encryptedPub})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recipients, want) {
		t.Fatal("recipients derived from identities do not match their public keys")
	}
}

func TestLoadIdentitiesRejectsUnusableFiles(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	for name, content := range map[string]string{
		"public key":         id.Recipient().String() + "\n",
		"age encrypted file": "age-encryption.org/v1\n-> X25519 abc\n",
		"armored age file":   "-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n-----END AGE ENCRYPTED FILE-----\n",
		"garbage PEM":        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
		"only comments":      "# nothing here\n",
	} {
		if _, err := loadIdentities([]string{writeTestFile(t, "id", []byte(content))}); err == nil {
			t.Fatalf("%s accepted as an identity", name)
		}
	}
}

func TestLoadIdentitiesPluginAndPostQuantum(t *testing.T) {
	pq, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	content := "# hardware token\n" + plugin.EncodeIdentity("yubikey", randomBytes(t, 20)) + "\n" + pq.String() + "\n"
	ids, err := loadIdentities([]string{writeTestFile(t, "ids.txt", []byte(content))})
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := ids[0].(*plugin.Identity); !ok || p.Name() != "yubikey" {
		t.Fatalf("identity %T, want yubikey *plugin.Identity", ids[0])
	}
	if _, ok := ids[1].(*age.HybridIdentity); !ok {
		t.Fatalf("identity type %T, want *age.HybridIdentity", ids[1])
	}
}

func runKeygenKeyFile(t *testing.T, output string) error {
	t.Helper()
	flagKeygenOutput, flagKeygenKeyFile = output, true
	t.Cleanup(func() { flagKeygenOutput, flagKeygenKeyFile = "", false })
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	return runKeygen(cmd, nil)
}

func TestKeygenWritesRandomKeyFile(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.key"), filepath.Join(dir, "b.key")
	if err := runKeygenKeyFile(t, a); err != nil {
		t.Fatal(err)
	}
	if err := runKeygenKeyFile(t, b); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != identityFileMode || info.Size() != crypto.MinKeyFileSize {
		t.Fatalf("key file mode %v size %d, want %v and %d", info.Mode().Perm(), info.Size(),
			os.FileMode(identityFileMode), crypto.MinKeyFileSize)
	}
	keys, err := readKeyFiles([]string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keys[0], keys[1]) {
		t.Fatal("two generated key files are identical")
	}
}

func TestKeygenKeyFileNeedsOutputAndNeverOverwrites(t *testing.T) {
	if err := runKeygenKeyFile(t, ""); err == nil {
		t.Fatal("key file written without --output")
	}
	path := writeTestFile(t, "existing.key", []byte("keep me"))
	if err := runKeygenKeyFile(t, path); err == nil {
		t.Fatal("existing file overwritten")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "keep me" {
		t.Fatalf("existing file changed: %q %v", got, err)
	}
}

func TestIdentityTypeWithoutPublicKeyIsRejected(t *testing.T) {
	scrypt, err := age.NewScryptIdentity("pass")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recipientsForIdentities([]age.Identity{scrypt}); err == nil {
		t.Fatal("identity without a public key accepted")
	}
}
