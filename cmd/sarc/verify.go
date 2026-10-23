// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	sarcio "github.com/iamvirul/sarc/io"
)

var flagSigners []string

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Check the archive checksum and signature, without a password",
	Long: "verify recomputes the SHA-256 checksum stored in the archive footer. It detects\n" +
		"accidental corruption (bad disks, truncated transfers) without decrypting anything.\n" +
		"The checksum alone is not keyed: tampering is detected by extract and list, which\n" +
		"authenticate every entry with the archive's keys.\n\n" +
		"A signed archive (archive --sign, or sign) also proves who created it: with --signer,\n" +
		"verify succeeds only if the archive is signed by one of the given public keys.",
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVarP(&flagArchive, "archive", "a", "", "archive path, or - for stdin (required)")
	verifyCmd.Flags().StringArrayVar(&flagSigners, "signer", nil,
		"trusted signer: an SSH public key (ssh-ed25519 AAAA...), or a .pub, authorized_keys, allowed_signers, or PEM public key file (repeatable); require a valid signature by one of them")
	_ = verifyCmd.MarkFlagRequired("archive")
}

var (
	errChecksumFailed = errors.New("integrity check FAILED: archive checksum mismatch (corrupted or modified)")
	errSignatureCheck = errors.New("signature check FAILED")
)

func runVerify(cmd *cobra.Command, args []string) error {
	signers, err := parseSigners(flagSigners)
	if err != nil {
		return err
	}
	in, err := openArchiveInput(flagArchive)
	if err != nil {
		return err
	}
	defer in.Close()

	report, err := sarcio.VerifyArchive(in)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	sigErr := reportSignature(out, report, signers)
	if !report.ChecksumOK {
		return errChecksumFailed
	}
	fmt.Fprintln(out, "integrity check PASSED")
	return sigErr
}

// reportSignature prints the signature status and returns errSignatureCheck when
// signers were required and none of them signed the archive validly, or when a
// signature is present but invalid.
func reportSignature(w io.Writer, report sarcio.VerifyReport, signers []trustedSigner) error {
	switch {
	case !report.Signed && len(signers) > 0:
		fmt.Fprintln(w, "signature MISSING: the archive is not signed")
		return errSignatureCheck
	case !report.Signed:
		return nil
	case report.SignatureErr != nil:
		fmt.Fprintln(w, "signature INVALID: it does not match the archive")
		return errSignatureCheck
	}
	signer := describeKey(report.Signer)
	if len(signers) == 0 {
		fmt.Fprintf(w, "signature valid, signed by %s; pass --signer to check it is a key you trust\n", signer)
		return nil
	}
	for _, s := range signers {
		if bytes.Equal(s.key.Marshal(), report.Signer.Marshal()) {
			fmt.Fprintf(w, "signature VALID: signed by %s, %s\n", signer, s.label)
			return nil
		}
	}
	fmt.Fprintf(w, "signature UNTRUSTED: signed by %s, which is not a given --signer\n", signer)
	return errSignatureCheck
}
