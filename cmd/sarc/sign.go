// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	sarcio "github.com/iamvirul/sarc/io"
)

var flagSigningKey string

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign an existing archive, without a password and without rewriting it",
	Long: "sign appends an SSH signature over the archive checksum, replacing any earlier\n" +
		"signature. Anyone can then check who signed it with sarc verify --signer, without the\n" +
		"password. The checksum is verified first, so a corrupted archive is never signed.",
	Args: cobra.NoArgs,
	RunE: runSign,
}

func init() {
	signCmd.Flags().StringVarP(&flagSigningKey, "signing-key", "s", "",
		"private key to sign with: OpenSSH (ssh-keygen, sarc keygen --signing) or PEM; ed25519, ECDSA, or RSA (required)")
	signCmd.Flags().StringVarP(&flagArchive, "archive", "a", "", "archive file to sign (required)")
	_ = signCmd.MarkFlagRequired("signing-key")
	_ = signCmd.MarkFlagRequired("archive")
}

func runSign(cmd *cobra.Command, args []string) error {
	if flagArchive == stdioPath || isRemote(flagArchive) {
		return errors.New("sign rewrites the end of a local archive file, not stdin or a storage URL; or sign while archiving with archive --sign")
	}
	signer, err := loadSigner(flagSigningKey)
	if err != nil {
		return err
	}
	if err := sarcio.SignArchiveFile(flagArchive, signer); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "signed %s with %s\n", flagArchive, describeKey(signer.PublicKey()))
	return nil
}
