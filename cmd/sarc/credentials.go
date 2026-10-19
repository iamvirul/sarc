// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"

	sarcio "github.com/iamvirul/sarc/io"
)

// agePublicKeyPrefix marks an inline age public key; any other --recipient value is a file.
const agePublicKeyPrefix = "age1"

var errNoCredential = errors.New("a --password or at least one --recipient is required")

// parseRecipients resolves --recipient values: an inline "age1..." public key, or the path
// of a recipients file in age format (one key per line, "#" comments allowed).
func parseRecipients(values []string) ([]age.Recipient, error) {
	var recipients []age.Recipient
	for _, v := range values {
		if strings.HasPrefix(v, agePublicKeyPrefix) {
			parsed, err := age.ParseRecipients(strings.NewReader(v))
			if err != nil {
				return nil, fmt.Errorf("invalid age recipient %q: %w", v, err)
			}
			recipients = append(recipients, parsed...)
			continue
		}
		f, err := os.Open(v)
		if err != nil {
			return nil, fmt.Errorf("cannot open recipients file: %w", err)
		}
		parsed, err := age.ParseRecipients(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("invalid recipients file %q: %w", v, err)
		}
		recipients = append(recipients, parsed...)
	}
	return recipients, nil
}

// loadIdentities reads age identity files (as written by age-keygen or sarc keygen).
// Parse errors are not wrapped, since they may quote secret key material.
func loadIdentities(paths []string) ([]age.Identity, error) {
	var identities []age.Identity
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("cannot open identity file: %w", err)
		}
		parsed, err := age.ParseIdentities(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("invalid identity file %q", path)
		}
		identities = append(identities, parsed...)
	}
	return identities, nil
}

// readerOptions validates that a password or identity was given and returns the
// extractor options for the identities.
func readerOptions() ([]sarcio.ExtractorOption, error) {
	if flagPassword == "" && len(flagIdentities) == 0 {
		return nil, errors.New("a --password or at least one --identity is required")
	}
	identities, err := loadIdentities(flagIdentities)
	if err != nil {
		return nil, err
	}
	if len(identities) == 0 {
		return nil, nil
	}
	return []sarcio.ExtractorOption{sarcio.WithIdentities(identities...)}, nil
}
