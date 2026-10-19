// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"
)

// identityFileMode keeps a written identity readable by its owner only.
const identityFileMode = 0o600

var flagKeygenOutput string

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an age X25519 identity for use with --recipient and --identity",
	Long: "keygen writes a new age identity in the same format as age-keygen. Share the printed\n" +
		"public key (age1...) with whoever archives for you; keep the identity file secret.",
	Args: cobra.NoArgs,
	RunE: runKeygen,
}

func init() {
	keygenCmd.Flags().StringVarP(&flagKeygenOutput, "output", "o", "", "identity file to create (default: stdout); never overwritten")
}

func runKeygen(cmd *cobra.Command, args []string) error {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generate identity: %w", err)
	}
	if flagKeygenOutput == "" {
		return writeIdentity(cmd.OutOrStdout(), identity)
	}
	f, err := os.OpenFile(flagKeygenOutput, os.O_WRONLY|os.O_CREATE|os.O_EXCL, identityFileMode)
	if err != nil {
		return fmt.Errorf("cannot create identity file: %w", err)
	}
	if err := writeIdentity(f, identity); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Public key: %s\n", identity.Recipient())
	return nil
}

// writeIdentity writes identity in age-keygen's format: creation time and public key as
// comments, then the secret key.
func writeIdentity(w io.Writer, identity *age.X25519Identity) error {
	_, err := fmt.Fprintf(w, "# created: %s\n# public key: %s\n%s\n",
		time.Now().UTC().Format(time.RFC3339), identity.Recipient(), identity)
	if err != nil {
		return fmt.Errorf("write identity: %w", err)
	}
	return nil
}
