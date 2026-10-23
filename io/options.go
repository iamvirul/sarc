// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"io"

	"filippo.io/age"

	"github.com/iamvirul/sarc/archive"
)

// ArchiverOption configures a StreamingArchiver or ConcurrentArchiver.
type ArchiverOption func(*archiverConfig)

type archiverConfig struct {
	compression   CompressionOptions
	ageRecipients []age.Recipient
	keyFiles      []archive.KeyFile
}

// WithCompression overrides the default compression options (CompressionAuto, level 3).
func WithCompression(opts CompressionOptions) ArchiverOption {
	return func(c *archiverConfig) { c.compression = opts }
}

// WithAgeRecipients adds age public-key recipients (for example parsed from "age1..."
// keys). Each can open the archive with the matching age identity, independently of
// the password and of each other.
func WithAgeRecipients(recipients ...age.Recipient) ArchiverOption {
	return func(c *archiverConfig) { c.ageRecipients = append(c.ageRecipients, recipients...) }
}

// WithKeyFileRecipients adds key file credentials. Each opens the archive on its own, or
// together with its password when one is set, independently of every other credential.
func WithKeyFileRecipients(keyFiles ...archive.KeyFile) ArchiverOption {
	return func(c *archiverConfig) { c.keyFiles = append(c.keyFiles, keyFiles...) }
}

// newArchiverConfig applies opts over the defaults.
func newArchiverConfig(opts []ArchiverOption) archiverConfig {
	cfg := archiverConfig{compression: DefaultCompressionOptions()}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// openArchiveWriter applies opts, builds the compression policy, and writes the archive
// header for password (empty for none) plus any key file and age recipients. At least
// one credential is required.
func openArchiveWriter(w io.Writer, password string, opts []ArchiverOption) (*archive.ArchiveWriter, *compressionPolicy, error) {
	cfg := newArchiverConfig(opts)
	policy, err := newCompressionPolicy(cfg.compression)
	if err != nil {
		return nil, nil, fatal(ErrCodeInvalidOption, "invalid compression options", err)
	}
	aw, err := newCredentialedWriter(w, password, cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := aw.WriteHeader(0); err != nil {
		return nil, nil, fatal(ErrCodeWriteFailed, "write header", err)
	}
	return aw, policy, nil
}

// newCredentialedWriter returns an ArchiveWriter openable with password (empty for none)
// and cfg's key file and age recipients, without writing the header. At least one
// credential is required.
func newCredentialedWriter(w io.Writer, password string, cfg archiverConfig) (*archive.ArchiveWriter, error) {
	if password == "" && len(cfg.keyFiles) == 0 && len(cfg.ageRecipients) == 0 {
		return nil, fatal(ErrCodeInvalidOption, "a password, key file, or age recipient is required", nil)
	}
	creds := archive.Credentials{KeyFiles: cfg.keyFiles, AgeRecipients: cfg.ageRecipients}
	if password != "" {
		creds.Passwords = []string{password}
	}
	aw, err := archive.NewArchiveWriter(w, creds)
	if err != nil {
		return nil, fatal(ErrCodeWriteFailed, "init archive writer", err)
	}
	return aw, nil
}

// ExtractorOption configures a SafeExtractor.
type ExtractorOption func(*SafeExtractor)

// WithIdentities adds age identities (for example parsed from an age-keygen file) to
// try against a Version2 archive's age recipients.
func WithIdentities(identities ...age.Identity) ExtractorOption {
	return func(se *SafeExtractor) { se.identities = append(se.identities, identities...) }
}

// WithRandomAccess gives the extractor random access to the archive it reads, as
// incremental archives require; ra must hold the same size bytes the extractor's
// reader yields. Without it, an incremental archive fails with ErrCodeInvalidOption.
func WithRandomAccess(ra io.ReaderAt, size int64) ExtractorOption {
	return func(se *SafeExtractor) { se.random, se.randomSize = ra, size }
}

// WithKeyFiles adds key file contents to try against a Version2 archive's key file
// recipients, alone or together with the extractor's password.
func WithKeyFiles(keys ...[]byte) ExtractorOption {
	return func(se *SafeExtractor) { se.keyFiles = append(se.keyFiles, keys...) }
}
