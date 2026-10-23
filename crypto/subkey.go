// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// HKDF info labels. Distinct labels give the file and header subkeys independent
// outputs even though both are expanded from the same master key.
const (
	fileSubkeyLabel   = "sarc file key"
	headerSubkeyLabel = "sarc header key"
	chunkIDLabel      = "sarc chunk id key"
	gearTableLabel    = "sarc chunker gear table"
)

// GearTableSize is the number of entries in a content-defined chunking gear table.
const GearTableSize = 256

// DeriveFileSubkey returns HKDF-SHA256-Expand(masterKey, "sarc file key" || salt, 32).
// masterKey must already be a uniformly random key (e.g. a PBKDF2 output), so the
// HKDF-Extract step is skipped as permitted by RFC 5869 section 3.3.
func DeriveFileSubkey(masterKey [KeySize]byte, salt [SaltSize]byte) ([KeySize]byte, error) {
	info := make([]byte, 0, len(fileSubkeyLabel)+SaltSize)
	info = append(info, fileSubkeyLabel...)
	info = append(info, salt[:]...)
	return expandSubkey(masterKey, string(info))
}

// DeriveHeaderSubkey returns HKDF-SHA256-Expand(masterKey, "sarc header key", 32).
func DeriveHeaderSubkey(masterKey [KeySize]byte) ([KeySize]byte, error) {
	return expandSubkey(masterKey, headerSubkeyLabel)
}

// DeriveChunkIDKey returns HKDF-SHA256-Expand(masterKey, "sarc chunk id key", 32), the
// HMAC key that names incremental archive chunks.
func DeriveChunkIDKey(masterKey [KeySize]byte) ([KeySize]byte, error) {
	return expandSubkey(masterKey, chunkIDLabel)
}

// DeriveGearTable returns the 256 64-bit gear values for content-defined chunking,
// expanded from masterKey with HKDF-SHA256 under "sarc chunker gear table". A secret
// table makes chunk boundaries depend on the key as well as the content.
func DeriveGearTable(masterKey [KeySize]byte) ([GearTableSize]uint64, error) {
	var table [GearTableSize]uint64
	raw, err := hkdf.Expand(sha256.New, masterKey[:], gearTableLabel, GearTableSize*8)
	if err != nil {
		return table, fmt.Errorf("crypto/subkey: hkdf expand: %w", err)
	}
	for i := range table {
		table[i] = binary.LittleEndian.Uint64(raw[i*8:])
	}
	return table, nil
}

func expandSubkey(masterKey [KeySize]byte, info string) ([KeySize]byte, error) {
	var key [KeySize]byte
	raw, err := hkdf.Expand(sha256.New, masterKey[:], info, KeySize)
	if err != nil {
		return key, fmt.Errorf("crypto/subkey: hkdf expand: %w", err)
	}
	copy(key[:], raw)
	return key, nil
}
