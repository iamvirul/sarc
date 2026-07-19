// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

const HMACSize = 32

// ComputeHMAC returns HMAC-SHA256(key, data).
// Must be called on plaintext before encryption.
func ComputeHMAC(key [KeySize]byte, data []byte) [HMACSize]byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write(data)
	var out [HMACSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// VerifyHMAC checks expected == HMAC-SHA256(key, data) in constant time.
func VerifyHMAC(key [KeySize]byte, data []byte, expected [HMACSize]byte) error {
	got := ComputeHMAC(key, data)
	if subtle.ConstantTimeCompare(got[:], expected[:]) != 1 {
		return fmt.Errorf("crypto/hmac: tag mismatch")
	}
	return nil
}
