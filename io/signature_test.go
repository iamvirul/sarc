// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"golang.org/x/crypto/ssh"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

// fakeArchive returns body followed by a valid footer for it.
func fakeArchive(body []byte) []byte {
	sum := sha256.Sum256(body)
	out := append(append([]byte{}, body...), sum[:]...)
	return append(out, make([]byte, archive.ReservedSize)...)
}

func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// signFake appends a signature block over data's footer checksum.
func signFake(t *testing.T, data []byte, signer ssh.Signer) []byte {
	t.Helper()
	checksum := data[len(data)-archive.FooterSize:][:archive.HMACSize]
	block, err := signatureBlock(checksum, signer)
	if err != nil {
		t.Fatal(err)
	}
	return append(bytes.Clone(data), block...)
}

func TestVerifyArchiveAcceptsValidChecksum(t *testing.T) {
	body := bytes.Repeat([]byte("sarc body "), 300_000) // spans several reads
	if r, err := VerifyArchive(bytes.NewReader(fakeArchive(body))); err != nil || !r.ChecksumOK || r.Signed {
		t.Fatalf("multi-chunk input: %+v %v", r, err)
	}
	// One byte per Read exercises the holdback across many reads.
	if r, err := VerifyArchive(iotest.OneByteReader(bytes.NewReader(fakeArchive(body[:50000])))); err != nil || !r.ChecksumOK {
		t.Fatalf("one-byte reads: %+v %v", r, err)
	}
	if r, err := VerifyArchive(bytes.NewReader(fakeArchive(nil))); err != nil || !r.ChecksumOK {
		t.Fatalf("footer-only input: %+v %v", r, err)
	}
}

func TestVerifyArchiveRejectsCorruptionAndShortInput(t *testing.T) {
	data := fakeArchive(bytes.Repeat([]byte{0x42}, 10_000))
	data[123] ^= 0x01
	if r, err := VerifyArchive(bytes.NewReader(data)); err != nil || r.ChecksumOK {
		t.Fatalf("corrupted body: %+v %v", r, err)
	}
	short := make([]byte, archive.FooterSize-1)
	var ae *ArchiveError
	if _, err := VerifyArchive(bytes.NewReader(short)); !errors.As(err, &ae) || ae.Code != ErrCodeTruncated {
		t.Fatalf("want %s, got %v", ErrCodeTruncated, err)
	}
}

func TestVerifyArchiveChecksSignatures(t *testing.T) {
	signer := newTestSigner(t)
	signed := signFake(t, fakeArchive(bytes.Repeat([]byte("signed "), 200_000)), signer)
	for name, src := range map[string]func() io.Reader{
		"whole":          func() io.Reader { return bytes.NewReader(signed) },
		"one-byte reads": func() io.Reader { return iotest.OneByteReader(bytes.NewReader(signed)) },
	} {
		rep, err := VerifyArchive(src())
		if err != nil || !rep.ChecksumOK || !rep.Signed || rep.SignatureErr != nil ||
			!bytes.Equal(rep.Signer.Marshal(), signer.PublicKey().Marshal()) {
			t.Fatalf("%s: %+v %v", name, rep, err)
		}
	}

	// A body change breaks both the checksum and the signature, since the signature is
	// checked against the recomputed checksum, not the stored footer.
	tampered := bytes.Clone(signed)
	tampered[500] ^= 1
	rep, err := VerifyArchive(bytes.NewReader(tampered))
	if err != nil || rep.ChecksumOK || !rep.Signed || !errors.Is(rep.SignatureErr, crypto.ErrBadSignature) {
		t.Fatalf("tampered body: %+v %v", rep, err)
	}

	// Flipping a signature byte breaks only the signature.
	badSig := bytes.Clone(signed)
	badSig[len(badSig)-archive.SignatureTrailerSize-5] ^= 1
	rep, err = VerifyArchive(bytes.NewReader(badSig))
	if err != nil || !rep.ChecksumOK || !rep.Signed || rep.SignatureErr == nil {
		t.Fatalf("tampered signature: %+v %v", rep, err)
	}
}

func TestSplitSignatureMatchesStreamingSplit(t *testing.T) {
	data := fakeArchive([]byte("body"))
	signed := signFake(t, data, newTestSigner(t))
	for _, d := range [][]byte{data, signed} {
		proper, sig, err := splitSignature(bytes.NewReader(d), int64(len(d)))
		if err != nil || proper != int64(len(data)) || (sig != nil) != (len(d) != len(data)) {
			t.Fatalf("splitSignature: proper %d sig %v err %v", proper, sig != nil, err)
		}
		streamProper, streamSig := splitSignatureTail(d)
		if len(streamProper) != len(data) || !bytes.Equal(streamSig, sig) {
			t.Fatal("streaming and random-access splits disagree")
		}
	}
}
