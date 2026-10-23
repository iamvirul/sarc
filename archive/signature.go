// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"encoding/binary"
	"fmt"
)

// A signed archive carries a signature block after its footer:
//
//	archive | signature | signature_len(4) | "SARCSIG1"
//
// The signature (an SSH signature, see crypto.SignMessage) is over the footer checksum,
// which commits to every archive byte before the footer, so verifying it needs no
// password. The block sits outside the archive proper: readers stop at the end marker,
// and signing an existing archive appends or replaces the block without touching the
// archive. An unsigned archive ends with the footer's zero reserved bytes, which never
// match the trailer magic.
const (
	// SignatureTrailerSize is the length of the length and magic after a signature.
	SignatureTrailerSize = 4 + len(signatureMagic)
	// MaxSignatureSize bounds a signature, which holds a public key and a signature of
	// at most a few hundred bytes for the largest RSA keys.
	MaxSignatureSize = 16 << 10

	signatureMagic = "SARCSIG1"
)

// AppendSignatureBlock appends the signature block for signature to dst.
func AppendSignatureBlock(dst, signature []byte) ([]byte, error) {
	if len(signature) == 0 || len(signature) > MaxSignatureSize {
		return nil, fmt.Errorf("archive/signature: signature is %d bytes, want 1 to %d", len(signature), MaxSignatureSize)
	}
	dst = append(dst, signature...)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(signature)))
	return append(dst, signatureMagic...), nil
}

// ParseSignatureTrailer reports whether tail, the last SignatureTrailerSize bytes of an
// archive file, ends a signature block, and if so the signature's length.
func ParseSignatureTrailer(tail []byte) (int, bool) {
	if len(tail) != SignatureTrailerSize || string(tail[4:]) != signatureMagic {
		return 0, false
	}
	n := binary.LittleEndian.Uint32(tail)
	if n == 0 || n > MaxSignatureSize {
		return 0, false
	}
	return int(n), true
}
