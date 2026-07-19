package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	NonceSize     = 12
	GCMTagSize    = 16
	BaseBlockSize = 64 * 1024 // 64 KB
)

// EncryptedBlock holds a single encrypted chunk along with its nonce.
// Nonce is stored plaintext (safe with GCM) so the receiver can decrypt without extra state.
type EncryptedBlock struct {
	Nonce      [NonceSize]byte
	Ciphertext []byte // includes 16-byte GCM auth tag at the end
}

// EncryptionManager performs AES-256-GCM block encryption using a derived key.
type EncryptionManager struct {
	gcm cipher.AEAD
}

// NewEncryptionManager constructs an EncryptionManager from a 32-byte AES-256 key.
func NewEncryptionManager(key [KeySize]byte) (*EncryptionManager, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("crypto/encryption: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto/encryption: new GCM: %w", err)
	}
	return &EncryptionManager{gcm: gcm}, nil
}

// EncryptBlock encrypts plaintext with a freshly generated random nonce.
// Each call produces an independent ciphertext even for identical plaintext.
func (em *EncryptionManager) EncryptBlock(plaintext []byte) (EncryptedBlock, error) {
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return EncryptedBlock{}, fmt.Errorf("crypto/encryption: generate nonce: %w", err)
	}
	ciphertext := em.gcm.Seal(nil, nonce[:], plaintext, nil)
	return EncryptedBlock{Nonce: nonce, Ciphertext: ciphertext}, nil
}

// DecryptBlock authenticates and decrypts a block produced by EncryptBlock.
// Returns an error if the GCM auth tag does not verify (tampered or wrong key).
func (em *EncryptionManager) DecryptBlock(block EncryptedBlock) ([]byte, error) {
	plaintext, err := em.gcm.Open(nil, block.Nonce[:], block.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto/encryption: decrypt block: authentication failed: %w", err)
	}
	return plaintext, nil
}

// EncryptStream reads from r in variable-size chunks and returns encrypted blocks.
// Chunk sizes vary around BaseBlockSize to prevent size-pattern analysis.
func (em *EncryptionManager) EncryptStream(r io.Reader, varGen VarianceGenerator) ([]EncryptedBlock, error) {
	var blocks []EncryptedBlock
	for {
		size := BaseBlockSize + varGen.Next()
		if size < 1 {
			size = 1
		}
		buf := make([]byte, size)
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			block, encErr := em.EncryptBlock(buf[:n])
			if encErr != nil {
				return nil, encErr
			}
			blocks = append(blocks, block)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("crypto/encryption: read stream: %w", err)
		}
	}
	return blocks, nil
}

// VarianceGenerator provides a block-size delta (can be negative) for each chunk.
type VarianceGenerator interface {
	Next() int
}

// RandomVarianceGenerator returns a variance in [-maxDelta, +maxDelta].
type RandomVarianceGenerator struct {
	maxDelta int
}

// NewRandomVarianceGenerator creates a generator with variance up to maxDelta bytes.
func NewRandomVarianceGenerator(maxDelta int) *RandomVarianceGenerator {
	return &RandomVarianceGenerator{maxDelta: maxDelta}
}

// Next returns a cryptographically random delta in [-maxDelta, +maxDelta].
func (g *RandomVarianceGenerator) Next() int {
	if g.maxDelta == 0 {
		return 0
	}
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return 0
	}
	raw := int(b[0])<<8 | int(b[1])
	span := 2*g.maxDelta + 1
	return (raw % span) - g.maxDelta
}
