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
// Version2: master_key = PBKDF2(password, archive_salt) once, then
// file_key = HKDF-Expand(master_key, entry_salt) and header_key = HKDF-Expand(master_key).
type KeySchedule struct {
	version   uint16
	legacy    *crypto.KeyDeriver
	masterKey [crypto.KeySize]byte
}

// NewKeySchedule returns the KeySchedule for version. For Version2 it runs PBKDF2 once
// over archiveSalt; for Version1 no work is done until FileKey is called.
func NewKeySchedule(password string, version uint16, archiveSalt [crypto.SaltSize]byte) (*KeySchedule, error) {
	kd := crypto.NewKeyDeriver(password)
	switch version {
	case Version1:
		return &KeySchedule{version: version, legacy: kd}, nil
	case Version2:
		return &KeySchedule{version: version, masterKey: kd.DeriveKey(archiveSalt)}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}
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
