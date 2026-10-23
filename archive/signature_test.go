// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package archive_test

import (
	"bytes"
	"testing"

	"github.com/iamvirul/sarc/archive"
)

func TestSignatureBlockRoundtrip(t *testing.T) {
	sig := bytes.Repeat([]byte{7}, 300)
	block, err := archive.AppendSignatureBlock([]byte("archive"), sig)
	if err != nil {
		t.Fatal(err)
	}
	n, ok := archive.ParseSignatureTrailer(block[len(block)-archive.SignatureTrailerSize:])
	if !ok || n != len(sig) {
		t.Fatalf("trailer: %d %v", n, ok)
	}
	if got := block[len(block)-archive.SignatureTrailerSize-n : len(block)-archive.SignatureTrailerSize]; !bytes.Equal(got, sig) {
		t.Fatal("signature bytes differ")
	}
	for _, size := range []int{0, archive.MaxSignatureSize + 1} {
		if _, err := archive.AppendSignatureBlock(nil, make([]byte, size)); err == nil {
			t.Fatalf("%d-byte signature accepted", size)
		}
	}
}

func TestUnsignedArchiveTailIsNotASignatureTrailer(t *testing.T) {
	var buf bytes.Buffer
	aw, err := archive.NewArchiveWriter(&buf, archive.Credentials{Passwords: []string{"sig-tail-test"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteHeader(0); err != nil {
		t.Fatal(err)
	}
	if err := aw.WriteFooter(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	if _, ok := archive.ParseSignatureTrailer(data[len(data)-archive.SignatureTrailerSize:]); ok {
		t.Fatal("unsigned archive tail parsed as a signature trailer")
	}
	if !bytes.Equal(aw.Checksum(), data[len(data)-archive.FooterSize:len(data)-archive.FooterSize+32]) {
		t.Fatal("Checksum does not match the footer")
	}
	bad := append(bytes.Clone(data), 0, 0, 0, 0)
	bad = append(bad, "SARCSIG1"...)
	if _, ok := archive.ParseSignatureTrailer(bad[len(bad)-archive.SignatureTrailerSize:]); ok {
		t.Fatal("zero-length signature trailer accepted")
	}
}
