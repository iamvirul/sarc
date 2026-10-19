// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
	"github.com/spf13/cobra"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
	sarcio "github.com/iamvirul/sarc/io"
)

const (
	// agePublicKeyPrefix and sshPublicKeyPrefix mark an inline public key; any other
	// --recipient value is a recipients file.
	agePublicKeyPrefix = "age1"
	sshPublicKeyPrefix = "ssh-"

	// recipientsFileSizeLimit and recipientLineLimit bound a recipients file, matching age.
	recipientsFileSizeLimit = 16 << 20
	recipientLineLimit      = 8 << 10
)

var errNoCredential = errors.New("a --password, --key, --recipient, or --identity is required")

// parseRecipient parses one public key: age X25519 (age1...), post-quantum hybrid
// (age1pq1...), tagged hardware (age1tag1...), plugin (age1<name>1..., run as
// age-plugin-<name>), or SSH (ssh-ed25519, ssh-rsa).
func parseRecipient(s string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(s, "age1tag1"), strings.HasPrefix(s, "age1tagpq1"):
		return tag.ParseRecipient(s)
	case strings.HasPrefix(s, "age1pq1"):
		return age.ParseHybridRecipient(s)
	case strings.HasPrefix(s, agePublicKeyPrefix) && strings.Count(s, "1") > 1:
		return plugin.NewRecipient(s, pluginUI())
	case strings.HasPrefix(s, agePublicKeyPrefix):
		return age.ParseX25519Recipient(s)
	case strings.HasPrefix(s, sshPublicKeyPrefix):
		return agessh.ParseRecipient(s)
	}
	return nil, errors.New("unknown recipient type")
}

// parseRecipients resolves --recipient values: an inline public key (see
// parseRecipient), or the path of a recipients file with one key per line ("#"
// comments allowed), such as an age recipients file or an SSH .pub file.
func parseRecipients(values []string) ([]age.Recipient, error) {
	var recipients []age.Recipient
	for _, v := range values {
		if strings.HasPrefix(v, agePublicKeyPrefix) || strings.HasPrefix(v, sshPublicKeyPrefix) {
			r, err := parseRecipient(v)
			if err != nil {
				return nil, fmt.Errorf("invalid recipient %q: %w", v, err)
			}
			recipients = append(recipients, r)
			continue
		}
		parsed, err := parseRecipientsFile(v)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, parsed...)
	}
	return recipients, nil
}

// parseRecipientsFile reads a recipients file. Errors name the line but never quote
// it, since a mistaken file may hold secrets.
func parseRecipientsFile(path string) ([]age.Recipient, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open recipients file: %w", err)
	}
	defer f.Close()
	lr := &io.LimitedReader{R: f, N: recipientsFileSizeLimit + 1}
	scanner := bufio.NewScanner(lr)
	var recipients []age.Recipient
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !utf8.ValidString(line) || len(line) > recipientLineLimit {
			return nil, fmt.Errorf("recipients file %q: invalid line %d", path, n)
		}
		if strings.HasPrefix(line, "AGE-") || strings.HasPrefix(line, "-----BEGIN") {
			return nil, fmt.Errorf("recipients file %q: line %d is a private key, not a public key", path, n)
		}
		r, err := parseRecipient(line)
		if err != nil {
			return nil, fmt.Errorf("recipients file %q: malformed recipient at line %d", path, n)
		}
		recipients = append(recipients, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read recipients file %q: %w", path, err)
	}
	if lr.N == 0 {
		return nil, fmt.Errorf("recipients file %q is too large", path)
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("recipients file %q has no recipients", path)
	}
	return recipients, nil
}

// readKeyFiles reads each key file whole. A key file is any file of MinKeyFileSize to
// MaxKeyFileSize bytes, used verbatim; sarc keygen --keyfile writes a random one.
func readKeyFiles(paths []string) ([][]byte, error) {
	keys := make([][]byte, 0, len(paths))
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("cannot open key file: %w", err)
		}
		key, err := io.ReadAll(io.LimitReader(f, crypto.MaxKeyFileSize+1))
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("read key file %q: %w", path, err)
		}
		if crypto.CheckKeyFileSize(key) != nil {
			return nil, fmt.Errorf("key file %q must be %d bytes to %d MiB, got %d bytes",
				path, crypto.MinKeyFileSize, crypto.MaxKeyFileSize>>20, len(key))
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// archiveCredentials turns the archive credential flags into the archiver's password
// and options. A password given with --key is bound to each key file, so it no longer
// opens the archive on its own.
func archiveCredentials() (string, []sarcio.ArchiverOption, error) {
	if flagPassword == "" && len(flagKeyFiles) == 0 && len(flagRecipients) == 0 && len(flagIdentities) == 0 {
		return "", nil, errNoCredential
	}
	if flagPassword != "" {
		if err := validatePassword(flagPassword); err != nil {
			return "", nil, err
		}
	}
	recipients, err := parseRecipients(flagRecipients)
	if err != nil {
		return "", nil, err
	}
	identities, err := loadIdentities(flagIdentities)
	if err != nil {
		return "", nil, err
	}
	fromIdentities, err := recipientsForIdentities(identities)
	if err != nil {
		return "", nil, err
	}
	keys, err := readKeyFiles(flagKeyFiles)
	if err != nil {
		return "", nil, err
	}
	if len(keys) > archive.MaxKeyFileRecipients {
		return "", nil, fmt.Errorf("at most %d --key files are allowed", archive.MaxKeyFileRecipients)
	}

	password := flagPassword
	opts := []sarcio.ArchiverOption{sarcio.WithAgeRecipients(append(recipients, fromIdentities...)...)}
	if len(keys) > 0 {
		keyFiles := make([]archive.KeyFile, len(keys))
		for i, key := range keys {
			keyFiles[i] = archive.KeyFile{Key: key, Password: password}
		}
		opts = append(opts, sarcio.WithKeyFileRecipients(keyFiles...))
		password = ""
	}
	return password, opts, nil
}

// addReaderCredentialFlags registers the credential flags of commands that open an archive.
func addReaderCredentialFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&flagPassword, "password", "p", "",
		"archive password, alone or together with --key")
	cmd.Flags().StringArrayVarP(&flagKeyFiles, "key", "k", nil, "key file (repeatable)")
	cmd.Flags().StringArrayVarP(&flagIdentities, "identity", "i", nil,
		"identity file: age, SSH private key, or plugin identity such as AGE-PLUGIN-YUBIKEY-1... (repeatable)")
}

// readerOptions validates that a password, key file, or identity was given and returns
// the extractor options for the key files and identities.
func readerOptions() ([]sarcio.ExtractorOption, error) {
	if flagPassword == "" && len(flagKeyFiles) == 0 && len(flagIdentities) == 0 {
		return nil, errors.New("a --password, --key, or --identity is required")
	}
	keys, err := readKeyFiles(flagKeyFiles)
	if err != nil {
		return nil, err
	}
	identities, err := loadIdentities(flagIdentities)
	if err != nil {
		return nil, err
	}
	var opts []sarcio.ExtractorOption
	if len(keys) > 0 {
		opts = append(opts, sarcio.WithKeyFiles(keys...))
	}
	if len(identities) > 0 {
		opts = append(opts, sarcio.WithIdentities(identities...))
	}
	return opts, nil
}
