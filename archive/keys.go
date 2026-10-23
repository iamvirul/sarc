// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"errors"
	"fmt"

	"github.com/iamvirul/sarc/crypto"
)

// ErrUnsupportedVersion is returned for an archive format version this build cannot handle.
var ErrUnsupportedVersion = errors.New("archive: unsupported format version")

// KeySchedule derives the per-entry and header keys for one archive according to
// its format version. It is immutable after construction and safe for concurrent use.
//
// Version1: file_key = PBKDF2(password, entry_salt). Read-only; no header key.
// Version2: the master key is the archive's random CEK, recovered from its recipient
// block (see recipients.go); file_key = HKDF-Expand(CEK, entry_salt) and
// header_key = HKDF-Expand(CEK).
type KeySchedule struct {
	version   uint16
	legacy    *crypto.KeyDeriver
	masterKey [crypto.KeySize]byte
}

// NewVersion1KeySchedule returns the read-only KeySchedule for a Version1 archive. No
// work is done until FileKey is called, which runs PBKDF2 per entry.
func NewVersion1KeySchedule(password string) *KeySchedule {
	return &KeySchedule{version: Version1, legacy: crypto.NewKeyDeriver(password)}
}

// NewVersion2KeySchedule returns the KeySchedule for a Version2 archive keyed by cek.
func NewVersion2KeySchedule(cek [crypto.KeySize]byte) *KeySchedule {
	return &KeySchedule{version: Version2, masterKey: cek}
}

// Version returns the archive format version this schedule derives keys for.
func (ks *KeySchedule) Version() uint16 {
	return ks.version
}

// FileKey returns the AES-256 key for the file entry identified by salt.
func (ks *KeySchedule) FileKey(salt [crypto.SaltSize]byte) ([crypto.KeySize]byte, error) {
	if ks.version == Version1 {
		return ks.legacy.DeriveKey(salt), nil
	}
	key, err := crypto.DeriveFileSubkey(ks.masterKey, salt)
	if err != nil {
		return key, fmt.Errorf("archive/keys: file key: %w", err)
	}
	return key, nil
}

// HeaderKey returns the key that seals the header file count. Version1 archives are
// never written by this build, so they have no header key.
func (ks *KeySchedule) HeaderKey() ([crypto.KeySize]byte, error) {
	if ks.version == Version1 {
		return [crypto.KeySize]byte{}, fmt.Errorf("%w: no header key for version %d", ErrUnsupportedVersion, ks.version)
	}
	key, err := crypto.DeriveHeaderSubkey(ks.masterKey)
	if err != nil {
		return key, fmt.Errorf("archive/keys: header key: %w", err)
	}
	return key, nil
}

// ChunkIDKey returns the HMAC key that names chunks in an incremental archive.
func (ks *KeySchedule) ChunkIDKey() ([crypto.KeySize]byte, error) {
	if ks.version == Version1 {
		return [crypto.KeySize]byte{}, fmt.Errorf("%w: no chunk keys for version %d", ErrUnsupportedVersion, ks.version)
	}
	key, err := crypto.DeriveChunkIDKey(ks.masterKey)
	if err != nil {
		return key, fmt.Errorf("archive/keys: chunk id key: %w", err)
	}
	return key, nil
}

// GearTable returns the secret gear table for content-defined chunking.
func (ks *KeySchedule) GearTable() ([crypto.GearTableSize]uint64, error) {
	if ks.version == Version1 {
		return [crypto.GearTableSize]uint64{}, fmt.Errorf("%w: no chunk keys for version %d", ErrUnsupportedVersion, ks.version)
	}
	table, err := crypto.DeriveGearTable(ks.masterKey)
	if err != nil {
		return table, fmt.Errorf("archive/keys: gear table: %w", err)
	}
	return table, nil
}
