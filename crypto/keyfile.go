// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
)

// A key file is a high-entropy secret stored as a file, so its wrap derives the
// key-encryption key with HKDF-SHA256 instead of a slow password KDF. A key file and
// password wrap needs both: the PBKDF2-stretched password and the key file bytes are
// combined in one HKDF, so neither credential alone opens it.

const (
	// MinKeyFileSize is the shortest accepted key file; shorter files cannot carry a
	// 256-bit secret.
	MinKeyFileSize = KeySize
	// MaxKeyFileSize bounds how much of a key file is read into memory.
	MaxKeyFileSize = 1 << 20

	keyFileWrapLabel         = "sarc key file recipient"
	keyFilePasswordWrapLabel = "sarc key file and password recipient"
)

// ErrKeyFileSize is returned for a key file outside [MinKeyFileSize, MaxKeyFileSize].
var ErrKeyFileSize = fmt.Errorf("crypto/keyfile: key file must be %d to %d bytes", MinKeyFileSize, MaxKeyFileSize)

// KeyFileWrap is a CEK sealed with AES-256-GCM under HKDF-SHA256(key file, Salt).
type KeyFileWrap struct {
	Salt   [SaltSize]byte
	Nonce  [NonceSize]byte
	Sealed [KeySize + GCMTagSize]byte
}

// CheckKeyFileSize returns ErrKeyFileSize unless key is an acceptable key file length.
func CheckKeyFileSize(key []byte) error {
	if len(key) < MinKeyFileSize || len(key) > MaxKeyFileSize {
		return ErrKeyFileSize
	}
	return nil
}

// WrapCEKWithKeyFile seals cek under key with a fresh salt and nonce.
func WrapCEKWithKeyFile(cek [KeySize]byte, key []byte) (KeyFileWrap, error) {
	if err := CheckKeyFileSize(key); err != nil {
		return KeyFileWrap{}, err
	}
	var w KeyFileWrap
	if err := randomSaltAndNonce(&w.Salt, &w.Nonce); err != nil {
		return KeyFileWrap{}, err
	}
	aead, err := keyFileAEAD(key, w.Salt)
	if err != nil {
		return KeyFileWrap{}, err
	}
	aead.Seal(w.Sealed[:0], w.Nonce[:], cek[:], []byte(keyFileWrapLabel))
	return w, nil
}

// UnwrapCEKWithKeyFile opens w with the first of keys that matches. It returns
// ErrWrongCredential when none does.
func UnwrapCEKWithKeyFile(w KeyFileWrap, keys [][]byte) ([KeySize]byte, error) {
	for _, key := range keys {
		if CheckKeyFileSize(key) != nil {
			continue
		}
		aead, err := keyFileAEAD(key, w.Salt)
		if err != nil {
			return [KeySize]byte{}, err
		}
		if cek, ok := openWrappedCEK(aead, w.Nonce, w.Sealed, keyFileWrapLabel); ok {
			return cek, nil
		}
	}
	return [KeySize]byte{}, ErrWrongCredential
}

// WrapCEKWithKeyFileAndPassword seals cek under a key derived from both key and
// password, with a fresh salt and nonce, at MinPasswordIterations.
func WrapCEKWithKeyFileAndPassword(cek [KeySize]byte, key []byte, password string) (PasswordWrap, error) {
	if err := CheckKeyFileSize(key); err != nil {
		return PasswordWrap{}, err
	}
	if password == "" {
		return PasswordWrap{}, errors.New("crypto/keyfile: empty password")
	}
	w := PasswordWrap{Iterations: MinPasswordIterations}
	if err := randomSaltAndNonce(&w.Salt, &w.Nonce); err != nil {
		return PasswordWrap{}, err
	}
	aead, err := keyFilePasswordAEAD(stretchPassword(password, w.Salt, w.Iterations), key, w.Salt)
	if err != nil {
		return PasswordWrap{}, err
	}
	aead.Seal(w.Sealed[:0], w.Nonce[:], cek[:], []byte(keyFilePasswordWrapLabel))
	return w, nil
}

// UnwrapCEKWithKeyFileAndPassword opens w with password and the first of keys that
// matches, running PBKDF2 once however many keys are tried. It returns
// ErrWrongCredential when no key matches together with password, and an error without
// deriving a key when w declares an iteration count out of range.
func UnwrapCEKWithKeyFileAndPassword(w PasswordWrap, keys [][]byte, password string) ([KeySize]byte, error) {
	if w.Iterations < MinPasswordIterations || w.Iterations > MaxPasswordIterations {
		return [KeySize]byte{}, fmt.Errorf("crypto/keyfile: wrap iterations %d out of range", w.Iterations)
	}
	if password == "" || len(keys) == 0 {
		return [KeySize]byte{}, ErrWrongCredential
	}
	stretched := stretchPassword(password, w.Salt, w.Iterations)
	for _, key := range keys {
		if CheckKeyFileSize(key) != nil {
			continue
		}
		aead, err := keyFilePasswordAEAD(stretched, key, w.Salt)
		if err != nil {
			return [KeySize]byte{}, err
		}
		if cek, ok := openWrappedCEK(aead, w.Nonce, w.Sealed, keyFilePasswordWrapLabel); ok {
			return cek, nil
		}
	}
	return [KeySize]byte{}, ErrWrongCredential
}

func keyFileAEAD(key []byte, salt [SaltSize]byte) (cipher.AEAD, error) {
	kek, err := hkdf.Key(sha256.New, key, salt[:], keyFileWrapLabel, KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto/keyfile: hkdf: %w", err)
	}
	return newWrapAEAD(kek)
}

// keyFilePasswordAEAD keys AES-256-GCM with HKDF-SHA256(stretched password || key file).
// The stretched password has a fixed length, so the concatenation is unambiguous.
func keyFilePasswordAEAD(stretched, key []byte, salt [SaltSize]byte) (cipher.AEAD, error) {
	secret := make([]byte, 0, len(stretched)+len(key))
	secret = append(append(secret, stretched...), key...)
	kek, err := hkdf.Key(sha256.New, secret, salt[:], keyFilePasswordWrapLabel, KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto/keyfile: hkdf: %w", err)
	}
	return newWrapAEAD(kek)
}

func openWrappedCEK(aead cipher.AEAD, nonce [NonceSize]byte, sealed [KeySize + GCMTagSize]byte, label string) ([KeySize]byte, bool) {
	var cek [KeySize]byte
	if _, err := aead.Open(cek[:0], nonce[:], sealed[:], []byte(label)); err != nil {
		return [KeySize]byte{}, false
	}
	return cek, true
}
