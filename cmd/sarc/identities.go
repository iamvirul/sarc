// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"
)

const (
	// identityFileSizeLimit bounds an age identity file and sshKeySizeLimit an SSH
	// private key, matching age.
	identityFileSizeLimit = 16 << 20
	sshKeySizeLimit       = 16 << 10

	pemPrefix        = "-----BEGIN"
	armoredAgePrefix = "-----BEGIN AGE ENCRYPTED FILE-----"
)

// loadIdentities reads identity files: age identities (as written by age-keygen or sarc
// keygen, including post-quantum and plugin identities such as AGE-PLUGIN-YUBIKEY-1...)
// or SSH private keys (ed25519 or RSA, optionally passphrase-protected). Errors never
// quote file contents, since they may hold secret key material.
func loadIdentities(paths []string) ([]age.Identity, error) {
	var identities []age.Identity
	for _, path := range paths {
		parsed, err := loadIdentityFile(path)
		if err != nil {
			return nil, err
		}
		identities = append(identities, parsed...)
	}
	return identities, nil
}

func loadIdentityFile(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open identity file: %w", err)
	}
	defer f.Close()
	b := bufio.NewReader(f)
	head, _ := b.Peek(1024)
	trimmed := bytes.TrimSpace(head)
	switch {
	case bytes.HasPrefix(trimmed, []byte("age-encryption.org/")), bytes.HasPrefix(trimmed, []byte(armoredAgePrefix)):
		return nil, fmt.Errorf("identity file %q is passphrase-encrypted, which sarc does not support; decrypt it with age first", path)
	case bytes.HasPrefix(trimmed, []byte(pemPrefix)):
		contents, err := io.ReadAll(io.LimitReader(b, sshKeySizeLimit+1))
		if err != nil {
			return nil, fmt.Errorf("read identity file %q: %w", path, err)
		}
		if len(contents) > sshKeySizeLimit {
			return nil, fmt.Errorf("identity file %q is too large for an SSH key", path)
		}
		return parseSSHIdentity(path, contents)
	default:
		return parseAgeIdentities(path, b)
	}
}

// parseAgeIdentities reads one age identity per line, skipping blanks and "#" comments.
func parseAgeIdentities(path string, r io.Reader) ([]age.Identity, error) {
	lr := &io.LimitedReader{R: r, N: identityFileSizeLimit + 1}
	scanner := bufio.NewScanner(lr)
	var identities []age.Identity
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, err := parseAgeIdentity(line)
		if err != nil {
			if strings.HasPrefix(line, agePublicKeyPrefix) || strings.HasPrefix(line, sshPublicKeyPrefix) {
				return nil, fmt.Errorf("identity file %q: line %d is a public key; pass it with --recipient", path, n)
			}
			return nil, fmt.Errorf("invalid identity file %q at line %d", path, n)
		}
		identities = append(identities, id)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read identity file %q: %w", path, err)
	}
	if lr.N == 0 {
		return nil, fmt.Errorf("identity file %q is too large", path)
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("identity file %q has no identities", path)
	}
	return identities, nil
}

func parseAgeIdentity(s string) (age.Identity, error) {
	switch {
	case strings.HasPrefix(s, "AGE-PLUGIN-"):
		return plugin.NewIdentity(s, pluginUI())
	case strings.HasPrefix(s, "AGE-SECRET-KEY-PQ-1"):
		return age.ParseHybridIdentity(s)
	case strings.HasPrefix(s, "AGE-SECRET-KEY-1"):
		return age.ParseX25519Identity(s)
	}
	return nil, errors.New("unknown identity type")
}

// parseSSHIdentity parses an SSH private key. A passphrase-protected key needs its
// public key, from the key itself or the adjacent .pub file, and prompts for the
// passphrase on the terminal only when an archive actually has a matching recipient.
func parseSSHIdentity(path string, pemBytes []byte) ([]age.Identity, error) {
	id, err := agessh.ParseIdentity(pemBytes)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		pub := missing.PublicKey
		if pub == nil {
			if pub, err = readSSHPublicKey(path + ".pub"); err != nil {
				return nil, err
			}
		}
		prompt := func() ([]byte, error) {
			return readSecret(fmt.Sprintf("Enter passphrase for %q:", path))
		}
		encrypted, err := agessh.NewEncryptedSSHIdentity(pub, pemBytes, prompt)
		if err != nil {
			return nil, fmt.Errorf("unsupported SSH key in %q: %w", path, err)
		}
		return []age.Identity{encrypted}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("malformed or unsupported SSH private key in %q (ed25519 and RSA are supported)", path)
	}
	return []age.Identity{id}, nil
}

func readSSHPublicKey(path string) (ssh.PublicKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("passphrase-protected SSH key needs its public key: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(contents)
	if err != nil {
		return nil, fmt.Errorf("malformed SSH public key %q: %w", path, err)
	}
	return pub, nil
}

// recipientsForIdentities returns the public key of each identity, so archive
// --identity encrypts to the holder of that identity. A passphrase-protected SSH key
// needs no passphrase for this.
func recipientsForIdentities(identities []age.Identity) ([]age.Recipient, error) {
	recipients := make([]age.Recipient, 0, len(identities))
	for _, id := range identities {
		var r age.Recipient
		switch id := id.(type) {
		case *age.X25519Identity:
			r = id.Recipient()
		case *age.HybridIdentity:
			r = id.Recipient()
		case *agessh.Ed25519Identity:
			r = id.Recipient()
		case *agessh.RSAIdentity:
			r = id.Recipient()
		case *agessh.EncryptedSSHIdentity:
			r = id.Recipient()
		case *plugin.Identity:
			r = id.Recipient()
		default:
			return nil, fmt.Errorf("identity type %T has no public key to archive for", id)
		}
		recipients = append(recipients, r)
	}
	return recipients, nil
}
