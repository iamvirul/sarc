// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

func newCodecPair(t *testing.T) (*archive.BlockCompressor, *archive.BlockDecompressor) {
	t.Helper()
	bc, err := archive.NewBlockCompressor(archive.DefaultCompressionLevel)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := archive.NewBlockDecompressor()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bd.Close)
	return bc, bd
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBlockCodecRoundtrip(t *testing.T) {
	bc, bd := newCodecPair(t)
	inputs := map[string][]byte{
		"empty":        {},
		"text":         bytes.Repeat([]byte("level=info msg=\"request completed\" status=200\n"), 4000),
		"random":       randomBytes(t, 64*1024),
		"max-chunk":    randomBytes(t, archive.MaxChunkSize),
		"single-byte":  {0x42},
		"binary-zeros": make([]byte, 100_000),
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			out, err := bd.Decompress(bc.Compress(nil, in))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, in) {
				t.Fatal("roundtrip mismatch")
			}
		})
	}
}

func TestBlockCompressorShrinksCompressibleInput(t *testing.T) {
	bc, _ := newCodecPair(t)
	in := bytes.Repeat([]byte("the same line again and again\n"), 8000)
	if out := bc.Compress(nil, in); len(out) >= len(in)/10 {
		t.Fatalf("compressed %d -> %d bytes, want at least 10x smaller", len(in), len(out))
	}
}

// TestCompressedIncompressibleChunkFitsMaxPayload guards the pipeline buffer sizing:
// a worst-case (random) MaxChunkSize chunk must encode within MaxPayloadSize.
func TestCompressedIncompressibleChunkFitsMaxPayload(t *testing.T) {
	bc, _ := newCodecPair(t)
	for i := 0; i < 8; i++ {
		out := bc.Compress(nil, randomBytes(t, archive.MaxChunkSize))
		if len(out) > archive.MaxPayloadSize {
			t.Fatalf("encoded %d bytes, exceeds MaxPayloadSize %d", len(out), archive.MaxPayloadSize)
		}
	}
}

func TestNewBlockCompressorRejectsInvalidLevel(t *testing.T) {
	for _, level := range []int{0, -1, archive.MaxCompressionLevel + 1} {
		if _, err := archive.NewBlockCompressor(level); !errors.Is(err, archive.ErrInvalidCompressionLevel) {
			t.Fatalf("level %d: want ErrInvalidCompressionLevel, got %v", level, err)
		}
	}
}

func TestNewBlockCompressorAcceptsFullLevelRange(t *testing.T) {
	for level := archive.MinCompressionLevel; level <= archive.MaxCompressionLevel; level++ {
		if _, err := archive.NewBlockCompressor(level); err != nil {
			t.Fatalf("level %d: %v", level, err)
		}
	}
}

// TestBlockDecompressorRejectsOversizedFrame confirms a frame decoding to more than
// MaxChunkSize is refused, bounding memory for a hostile or corrupted payload.
func TestBlockDecompressorRejectsOversizedFrame(t *testing.T) {
	bc, bd := newCodecPair(t)
	for _, size := range []int{archive.MaxChunkSize + 1, 4 * archive.MaxChunkSize} {
		bomb := bc.Compress(nil, make([]byte, size))
		if _, err := bd.Decompress(bomb); !errors.Is(err, archive.ErrBlockTooLarge) {
			t.Fatalf("decoded size %d: want ErrBlockTooLarge, got %v", size, err)
		}
	}
}

func TestBlockDecompressorRejectsGarbage(t *testing.T) {
	_, bd := newCodecPair(t)
	if _, err := bd.Decompress(randomBytes(t, 1024)); err == nil {
		t.Fatal("random bytes decoded as a zstd frame")
	}
}

func TestMetadataCodecRoundtrip(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	mm, err := archive.NewMetadataManager(crypto.NewKeyDeriver("codec-meta").DeriveKey(salt))
	if err != nil {
		t.Fatal(err)
	}
	for _, codec := range []archive.Codec{archive.CodecNone, archive.CodecZstd} {
		block, err := mm.Seal(archive.PlaintextMetadata{EncryptedFilename: []byte("f"), Codec: codec})
		if err != nil {
			t.Fatal(err)
		}
		got, err := mm.Open(block)
		if err != nil {
			t.Fatal(err)
		}
		if got.Codec != codec {
			t.Fatalf("codec = %v, want %v", got.Codec, codec)
		}
	}
}

func TestMetadataSealRejectsUnknownCodec(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	mm, err := archive.NewMetadataManager(crypto.NewKeyDeriver("codec-meta").DeriveKey(salt))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mm.Seal(archive.PlaintextMetadata{Codec: archive.Codec(7)}); err == nil {
		t.Fatal("sealed metadata with an unknown codec")
	}
}

func TestCompressingFrameBuilderChunkRoundtrip(t *testing.T) {
	bc, bd := newCodecPair(t)
	salt, _ := crypto.GenerateSalt()
	key := crypto.NewKeyDeriver("compressing-frame").DeriveKey(salt)
	fb, err := archive.NewCompressingFrameBuilder(key, bc)
	if err != nil {
		t.Fatal(err)
	}
	if fb.Codec() != archive.CodecZstd {
		t.Fatalf("codec = %v, want zstd", fb.Codec())
	}
	em, err := crypto.NewEncryptionManager(key)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := bytes.Repeat([]byte("frame builder compression payload "), 5000)
	dst := make([]byte, 0, archive.MaxPayloadSize+crypto.GCMTagSize)
	db, err := fb.EncryptChunkInto(plaintext, dst)
	if err != nil {
		t.Fatal(err)
	}
	if &db.Ciphertext[0] != &dst[:1][0] {
		t.Fatal("ciphertext was not written in place into dst")
	}
	if len(db.Ciphertext) >= len(plaintext) {
		t.Fatalf("ciphertext %d bytes, want smaller than plaintext %d", len(db.Ciphertext), len(plaintext))
	}

	payload, err := em.DecryptBlock(crypto.EncryptedBlock{Nonce: db.Nonce, Ciphertext: db.Ciphertext})
	if err != nil {
		t.Fatal(err)
	}
	got, err := bd.Decompress(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted, decompressed chunk does not match plaintext")
	}
}

func TestNewCompressingFrameBuilderRejectsNilCompressor(t *testing.T) {
	salt, _ := crypto.GenerateSalt()
	if _, err := archive.NewCompressingFrameBuilder(crypto.NewKeyDeriver("x").DeriveKey(salt), nil); err == nil {
		t.Fatal("accepted nil compressor")
	}
}
