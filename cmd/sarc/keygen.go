// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/iamvirul/sarc/crypto"
)

// identityFileMode keeps a written identity or key file readable by its owner only.
const identityFileMode = 0o600

var (
	flagKeygenOutput  string
	flagKeygenKeyFile bool
	flagKeygenSigning bool
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an age identity (for --recipient and --identity) or a key file (for --key)",
	Long: "keygen writes a new age identity in the same format as age-keygen. Share the printed\n" +
		"public key (age1...) with whoever archives for you; keep the identity file secret.\n\n" +
		"With --keyfile it writes a random 32-byte key file instead, for --key. Anyone with the\n" +
		"key file can open archives made with it, so store it like a password (for example on a\n" +
		"USB drive) and keep a backup: a lost key file cannot be recovered.\n\n" +
		"With --signing it writes an Ed25519 signing key in OpenSSH format for archive --sign and\n" +
		"sign, and its public key to <output>.pub for verify --signer. Existing SSH keys work too.",
	Args: cobra.NoArgs,
	RunE: runKeygen,
}

func init() {
	keygenCmd.Flags().StringVarP(&flagKeygenOutput, "output", "o", "",
		"file to create (default: stdout, identities only); never overwritten")
	keygenCmd.Flags().BoolVar(&flagKeygenKeyFile, "keyfile", false,
		"write a random 32-byte key file for --key instead of an age identity (requires --output)")
	keygenCmd.Flags().BoolVar(&flagKeygenSigning, "signing", false,
		"write an Ed25519 signing key to --output and its public key to <output>.pub (requires --output)")
	keygenCmd.MarkFlagsMutuallyExclusive("keyfile", "signing")
}

func runKeygen(cmd *cobra.Command, args []string) error {
	if flagKeygenKeyFile {
		return writeKeyFile(cmd, flagKeygenOutput)
	}
	if flagKeygenSigning {
		if flagKeygenOutput == "" {
			return errors.New("--signing requires --output")
		}
		pub, err := writeSigningKey(flagKeygenOutput)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Signing key written to %s; public key %s.pub: %s\n",
			flagKeygenOutput, flagKeygenOutput, describeKey(pub))
		return nil
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generate identity: %w", err)
	}
	if flagKeygenOutput == "" {
		return writeIdentity(cmd.OutOrStdout(), identity)
	}
	f, err := createSecretFile(flagKeygenOutput)
	if err != nil {
		return err
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

// writeKeyFile creates path holding MinKeyFileSize random bytes from crypto/rand.
func writeKeyFile(cmd *cobra.Command, path string) error {
	if path == "" {
		return errors.New("--keyfile requires --output")
	}
	key := make([]byte, crypto.MinKeyFileSize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate key file: %w", err)
	}
	f, err := createSecretFile(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		return fmt.Errorf("write key file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Key file written to %s; keep it secret and backed up\n", path)
	return nil
}

// createSecretFile creates path for writing, readable by its owner only, and fails if
// it already exists.
func createSecretFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, identityFileMode)
	if err != nil {
		return nil, fmt.Errorf("cannot create %s: %w", path, err)
	}
	return f, nil
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
