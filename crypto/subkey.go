// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// HKDF info labels. Distinct labels give the file and header subkeys independent
// outputs even though both are expanded from the same master key.
const (
	fileSubkeyLabel   = "sarc file key"
	headerSubkeyLabel = "sarc header key"
)

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

func expandSubkey(masterKey [KeySize]byte, info string) ([KeySize]byte, error) {
	var key [KeySize]byte
	raw, err := hkdf.Expand(sha256.New, masterKey[:], info, KeySize)
	if err != nil {
		return key, fmt.Errorf("crypto/subkey: hkdf expand: %w", err)
	}
	copy(key[:], raw)
	return key, nil
}
