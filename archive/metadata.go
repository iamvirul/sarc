// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/iamvirul/sarc/crypto"
)

// MetadataManager seals and opens per-file metadata using a file-specific key.
type MetadataManager struct {
	em *crypto.EncryptionManager
}

// NewMetadataManager returns a MetadataManager bound to key.
func NewMetadataManager(key [crypto.KeySize]byte) (*MetadataManager, error) {
	em, err := crypto.NewEncryptionManager(key)
	if err != nil {
		return nil, fmt.Errorf("archive/metadata: init encryption: %w", err)
	}
	return &MetadataManager{em: em}, nil
}

// Seal encrypts pm into a MetadataBlock.
func (mm *MetadataManager) Seal(pm PlaintextMetadata) (MetadataBlock, error) {
	raw, err := marshalMetadata(pm)
	if err != nil {
		return MetadataBlock{}, fmt.Errorf("archive/metadata: marshal: %w", err)
	}
	block, err := mm.em.EncryptBlock(raw)
	if err != nil {
		return MetadataBlock{}, fmt.Errorf("archive/metadata: encrypt: %w", err)
	}
	return MetadataBlock{Nonce: block.Nonce, Ciphertext: block.Ciphertext}, nil
}

// Open authenticates and decrypts mb into PlaintextMetadata.
func (mm *MetadataManager) Open(mb MetadataBlock) (PlaintextMetadata, error) {
	raw, err := mm.em.DecryptBlock(crypto.EncryptedBlock{
		Nonce:      mb.Nonce,
		Ciphertext: mb.Ciphertext,
	})
	if err != nil {
		return PlaintextMetadata{}, fmt.Errorf("archive/metadata: decrypt: %w", err)
	}
	pm, err := unmarshalMetadata(raw)
	if err != nil {
		return PlaintextMetadata{}, fmt.Errorf("archive/metadata: unmarshal: %w", err)
	}
	return pm, nil
}

// BucketizeSize maps an exact byte count to a SizeBucket.
func BucketizeSize(n int64) SizeBucket {
	switch {
	case n <= 1_024:
		return BucketTiny
	case n <= 10_240:
		return BucketSmall
	case n <= 102_400:
		return BucketMedium
	case n <= 1_048_576:
		return BucketLarge
	default:
		return BucketHuge
	}
}

// HashTimestamp returns HMAC-SHA256(salt, day-truncated unix timestamp of t).
func HashTimestamp(salt [crypto.SaltSize]byte, t time.Time) [32]byte {
	day := t.UTC().Truncate(24 * time.Hour).Unix()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(day))
	mac := hmac.New(sha256.New, salt[:])
	mac.Write(buf[:])
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// Wire layout: [2] filename len | [N] filename | [1] bucket | [32] ts hash | [4] perms
func marshalMetadata(pm PlaintextMetadata) ([]byte, error) {
	fnLen := len(pm.EncryptedFilename)
	if fnLen > 0xFFFF {
		return nil, fmt.Errorf("archive/metadata: filename too long (%d bytes)", fnLen)
	}
	buf := make([]byte, 2+fnLen+1+32+4)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(fnLen))
	copy(buf[2:], pm.EncryptedFilename)
	off := 2 + fnLen
	buf[off] = byte(pm.SizeBucket)
	off++
	copy(buf[off:off+32], pm.TimestampHash[:])
	off += 32
	binary.LittleEndian.PutUint32(buf[off:off+4], pm.Permissions)
	return buf, nil
}

func unmarshalMetadata(b []byte) (PlaintextMetadata, error) {
	if len(b) < 2 {
		return PlaintextMetadata{}, fmt.Errorf("archive/metadata: truncated")
	}
	fnLen := int(binary.LittleEndian.Uint16(b[0:2]))
	need := 2 + fnLen + 1 + 32 + 4
	if len(b) < need {
		return PlaintextMetadata{}, fmt.Errorf("archive/metadata: too short: need %d got %d", need, len(b))
	}
	var pm PlaintextMetadata
	pm.EncryptedFilename = make([]byte, fnLen)
	copy(pm.EncryptedFilename, b[2:2+fnLen])
	off := 2 + fnLen
	pm.SizeBucket = SizeBucket(b[off])
	off++
	copy(pm.TimestampHash[:], b[off:off+32])
	off += 32
	pm.Permissions = binary.LittleEndian.Uint32(b[off : off+4])
	return pm, nil
}
