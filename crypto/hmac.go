package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

const HMACSize = 32

// ComputeHMAC returns HMAC-SHA256(data) keyed with key.
// Call this on plaintext BEFORE encryption so the stored digest covers original content.
func ComputeHMAC(key [KeySize]byte, data []byte) [HMACSize]byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write(data)
	var out [HMACSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// VerifyHMAC checks that expected == HMAC-SHA256(key, data) using a constant-time comparison.
// Returns an error if the tag does not match, preventing timing side-channel attacks.
func VerifyHMAC(key [KeySize]byte, data []byte, expected [HMACSize]byte) error {
	got := ComputeHMAC(key, data)
	if subtle.ConstantTimeCompare(got[:], expected[:]) != 1 {
		return fmt.Errorf("crypto/hmac: integrity check failed: tag mismatch")
	}
	return nil
}
