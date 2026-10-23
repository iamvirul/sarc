// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"crypto/subtle"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/iamvirul/sarc/archive"
	"github.com/iamvirul/sarc/crypto"
)

const (
	// verifyHoldSize is how much of the end of a stream VerifyArchive holds back: enough
	// for the footer and the largest signature block.
	verifyHoldSize = archive.FooterSize + archive.MaxSignatureSize + archive.SignatureTrailerSize
	// verifyReadSize is how much VerifyArchive reads at a time.
	verifyReadSize = 1 << 20
)

// VerifyReport is the outcome of VerifyArchive.
type VerifyReport struct {
	ChecksumOK bool
	Signed     bool
	// Signer is the signing key when the signature verifies against the recomputed
	// checksum; it is not checked against any trusted key.
	Signer ssh.PublicKey
	// SignatureErr is why the signature does not verify, when Signed.
	SignatureErr error
}

// VerifyArchive reads an archive once from r, without a password, recomputes its footer
// checksum, and verifies its signature, if it carries one, against the recomputed
// checksum. It holds back the end of the stream instead of seeking, so it works on
// pipes.
func VerifyArchive(r io.Reader) (VerifyReport, error) {
	sum := archive.NewArchiveChecksum()
	work := make([]byte, verifyHoldSize+verifyReadSize)
	held := 0
	for {
		n, err := r.Read(work[held:])
		held += n
		if held > verifyHoldSize {
			sum.Write(work[:held-verifyHoldSize])
			copy(work, work[held-verifyHoldSize:held])
			held = verifyHoldSize
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return VerifyReport{}, fatal(ErrCodeReadFailed, "read archive", err)
		}
	}
	proper, signature := splitSignatureTail(work[:held])
	if len(proper) < archive.FooterSize {
		return VerifyReport{}, fatal(ErrCodeTruncated, "archive too small to contain a footer", nil)
	}
	sum.Write(proper[:len(proper)-archive.FooterSize])
	computed := sum.Sum(nil)
	stored := proper[len(proper)-archive.FooterSize:][:archive.HMACSize]
	report := VerifyReport{ChecksumOK: subtle.ConstantTimeCompare(computed, stored) == 1}
	if signature != nil {
		report.Signed = true
		report.Signer, report.SignatureErr = crypto.VerifyMessage(signature, computed)
	}
	return report, nil
}

// splitSignatureTail splits the end of an archive into the archive proper and its
// signature, which is nil when the archive is unsigned.
func splitSignatureTail(tail []byte) ([]byte, []byte) {
	if len(tail) < archive.SignatureTrailerSize {
		return tail, nil
	}
	n, ok := archive.ParseSignatureTrailer(tail[len(tail)-archive.SignatureTrailerSize:])
	if !ok || n+archive.SignatureTrailerSize+archive.FooterSize > len(tail) {
		return tail, nil
	}
	start := len(tail) - archive.SignatureTrailerSize - n
	return tail[:start], tail[start : len(tail)-archive.SignatureTrailerSize]
}

// splitSignature returns the size of the archive proper in a file of size bytes and its
// signature, which is nil when the archive is unsigned.
func splitSignature(ra io.ReaderAt, size int64) (int64, []byte, error) {
	if size < int64(archive.SignatureTrailerSize+archive.FooterSize) {
		return size, nil, nil
	}
	trailer := make([]byte, archive.SignatureTrailerSize)
	if _, err := ra.ReadAt(trailer, size-int64(len(trailer))); err != nil {
		return 0, nil, fatal(ErrCodeReadFailed, "read archive end", err)
	}
	n, ok := archive.ParseSignatureTrailer(trailer)
	if !ok || int64(n+archive.SignatureTrailerSize+archive.FooterSize) > size {
		return size, nil, nil
	}
	proper := size - int64(archive.SignatureTrailerSize+n)
	signature := make([]byte, n)
	if _, err := ra.ReadAt(signature, proper); err != nil {
		return 0, nil, fatal(ErrCodeReadFailed, "read signature", err)
	}
	return proper, signature, nil
}

// signatureBlock signs checksum with signer and returns the signature block.
func signatureBlock(checksum []byte, signer ssh.Signer) ([]byte, error) {
	signature, err := crypto.SignMessage(signer, checksum)
	if err != nil {
		return nil, fatal(ErrCodeInvalidOption, "sign archive", err)
	}
	block, err := archive.AppendSignatureBlock(nil, signature)
	if err != nil {
		return nil, fatal(ErrCodeInvalidOption, "sign archive", err)
	}
	return block, nil
}

// finishArchive writes the footer and, when signer is set, a signature block after it.
func finishArchive(aw *archive.ArchiveWriter, w io.Writer, signer ssh.Signer) error {
	if err := aw.WriteFooter(); err != nil {
		return fatal(ErrCodeWriteFailed, "write footer", err)
	}
	if signer == nil {
		return nil
	}
	block, err := signatureBlock(aw.Checksum(), signer)
	if err != nil {
		return err
	}
	if _, err := w.Write(block); err != nil {
		return fatal(ErrCodeWriteFailed, "write signature", err)
	}
	return nil
}

// writeSignature signs checksum and writes the signature block at offset, the end of
// the archive proper, replacing anything after it, then syncs.
func writeSignature(f *os.File, offset int64, checksum []byte, signer ssh.Signer) error {
	block, err := signatureBlock(checksum, signer)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(block, offset); err != nil {
		return fatal(ErrCodeWriteFailed, "write signature", err)
	}
	return truncateAndSync(f, offset+int64(len(block)))
}

// archiveChecksum recomputes the footer checksum of the archive proper (the first
// proper bytes of ra) and returns it, or fails when it does not match the footer.
func archiveChecksum(ra io.ReaderAt, proper int64) ([]byte, error) {
	if proper < int64(len(archive.Magic)+archive.FooterSize) {
		return nil, fatal(ErrCodeTruncated, "archive too small to contain a footer", nil)
	}
	var magic [4]byte
	if _, err := ra.ReadAt(magic[:], 0); err != nil {
		return nil, fatal(ErrCodeReadFailed, "read archive", err)
	}
	if magic != archive.Magic {
		return nil, fatal(ErrCodeBadMagic, "not a sarc archive", nil)
	}
	sum := archive.NewArchiveChecksum()
	if _, err := io.Copy(sum, io.NewSectionReader(ra, 0, proper-archive.FooterSize)); err != nil {
		return nil, fatal(ErrCodeReadFailed, "read archive", err)
	}
	stored := make([]byte, archive.HMACSize)
	if _, err := ra.ReadAt(stored, proper-archive.FooterSize); err != nil {
		return nil, fatal(ErrCodeReadFailed, "read footer", err)
	}
	computed := sum.Sum(nil)
	if subtle.ConstantTimeCompare(computed, stored) != 1 {
		return nil, fatal(ErrCodeIntegrityFail, "archive checksum mismatch; refusing to sign a corrupted archive", nil)
	}
	return computed, nil
}

// SignArchiveFile signs the archive file at path with signer, replacing any signature
// it has, without decrypting or rewriting it. It first recomputes the footer checksum
// and refuses an archive whose checksum does not match.
func SignArchiveFile(path string, signer ssh.Signer) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fatal(ErrCodeReadFailed, "open archive", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fatal(ErrCodeReadFailed, "stat archive", err)
	}
	proper, _, err := splitSignature(f, info.Size())
	if err != nil {
		return err
	}
	checksum, err := archiveChecksum(f, proper)
	if err != nil {
		return err
	}
	return writeSignature(f, proper, checksum, signer)
}

// signedBy reports whether signature is a valid signature by pub over checksum.
func signedBy(signature, checksum []byte, pub ssh.PublicKey) bool {
	got, err := crypto.VerifyMessage(signature, checksum)
	return err == nil && subtle.ConstantTimeCompare(got.Marshal(), pub.Marshal()) == 1
}
