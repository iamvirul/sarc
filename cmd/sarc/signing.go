// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// signingKeyComment labels keys written by sarc keygen --signing.
const signingKeyComment = "sarc signing key"

// trustedSigner is a public key accepted by verify --signer, with the label it was
// given (its comment, or the value it came from).
type trustedSigner struct {
	key   ssh.PublicKey
	label string
}

// loadSigner reads a private key for signing: an OpenSSH key (as from ssh-keygen or
// sarc keygen --signing) or a PEM key (PKCS#8, PKCS#1, or SEC 1). A passphrase-protected
// key prompts on the terminal. Errors never quote the file.
func loadSigner(path string) (ssh.Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open signing key: %w", err)
	}
	pemBytes, err := io.ReadAll(io.LimitReader(f, sshKeySizeLimit+1))
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("read signing key %q: %w", path, err)
	}
	if len(pemBytes) > sshKeySizeLimit {
		return nil, fmt.Errorf("signing key %q is too large", path)
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		passphrase, perr := readSecret(fmt.Sprintf("Enter passphrase for %q:", path))
		if perr != nil {
			return nil, perr
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, passphrase)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid or unsupported signing key %q (ed25519, ECDSA, and RSA are supported)", path)
	}
	return signer, nil
}

// parseSigners resolves --signer values: an inline public key ("ssh-ed25519 AAAA..."),
// or a file of them in authorized_keys or allowed_signers form, or a PEM public key.
func parseSigners(values []string) ([]trustedSigner, error) {
	var signers []trustedSigner
	for _, v := range values {
		if isInlinePublicKey(v) {
			key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(v))
			if err != nil {
				return nil, fmt.Errorf("invalid --signer public key: %w", err)
			}
			signers = append(signers, trustedSigner{key: key, label: labelFor(comment, "inline key")})
			continue
		}
		parsed, err := parseSignerFile(v)
		if err != nil {
			return nil, err
		}
		signers = append(signers, parsed...)
	}
	return signers, nil
}

func isInlinePublicKey(v string) bool {
	for _, prefix := range []string{"ssh-", "ecdsa-", "sk-"} {
		if strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}

func parseSignerFile(path string) ([]trustedSigner, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open signer public key: %w", err)
	}
	if block, _ := pem.Decode(contents); block != nil {
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("%q is not a public key", path)
		}
		raw, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid public key %q: %w", path, err)
		}
		key, err := ssh.NewPublicKey(raw)
		if err != nil {
			return nil, fmt.Errorf("unsupported public key %q: %w", path, err)
		}
		return []trustedSigner{{key: key, label: path}}, nil
	}
	var signers []trustedSigner
	for rest := contents; len(bytes.TrimSpace(rest)) > 0; {
		key, comment, _, next, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			return nil, fmt.Errorf("invalid signer public key file %q", path)
		}
		signers = append(signers, trustedSigner{key: key, label: labelFor(comment, path)})
		rest = next
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("signer public key file %q has no keys", path)
	}
	return signers, nil
}

func labelFor(comment, fallback string) string {
	if comment != "" {
		return comment
	}
	return fallback
}

// describeKey renders a public key as its type and SHA-256 fingerprint.
func describeKey(key ssh.PublicKey) string {
	return fmt.Sprintf("%s (%s)", ssh.FingerprintSHA256(key), key.Type())
}

// writeSigningKey generates an Ed25519 signing key and writes the private key to path
// (OpenSSH format, owner-only) and the public key to path.pub. Neither file is
// overwritten. It returns the public key.
func writeSigningKey(path string) (ssh.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, signingKeyComment)
	if err != nil {
		return nil, fmt.Errorf("encode signing key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	pubLine := append(bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshPub)), " "+signingKeyComment+"\n"...)
	pubPath := path + ".pub"
	if _, err := os.Stat(pubPath); err == nil {
		return nil, fmt.Errorf("cannot create %s: file exists", pubPath)
	}
	if err := writeNewFile(path, pem.EncodeToMemory(block), identityFileMode); err != nil {
		return nil, err
	}
	if err := writeNewFile(pubPath, pubLine, 0o644); err != nil {
		os.Remove(path)
		return nil, err
	}
	return sshPub, nil
}

// writeNewFile creates path with perm and contents, failing if it exists.
func writeNewFile(path string, contents []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", path, err)
	}
	if _, err := f.Write(contents); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
