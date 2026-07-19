// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/iamvirul/sarc/archive"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify archive integrity without decryption",
	RunE:  runVerify,
}

func init() {
	verifyCmd.Flags().StringVarP(&flagArchive, "archive", "a", "", "archive path (required)")
	_ = verifyCmd.MarkFlagRequired("archive")
}

func runVerify(cmd *cobra.Command, args []string) error {
	f, err := os.Open(flagArchive)
	if err != nil {
		return fmt.Errorf("cannot open archive: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat archive: %w", err)
	}
	footerSize := int64(archive.HMACSize + archive.ReservedSize)
	if info.Size() < footerSize {
		return fmt.Errorf("archive too small to contain a valid footer")
	}

	bodySize := info.Size() - footerSize
	bodyReader := io.LimitReader(f, bodySize)

	h := sha256.New()
	if _, err := io.Copy(h, bodyReader); err != nil {
		return fmt.Errorf("read archive body: %w", err)
	}
	computed := h.Sum(nil)

	var storedHMAC [archive.HMACSize]byte
	if _, err := io.ReadFull(f, storedHMAC[:]); err != nil {
		return fmt.Errorf("read footer HMAC: %w", err)
	}

	// Constant-time comparison to avoid timing leaks.
	match := true
	for i := range storedHMAC {
		if storedHMAC[i] != computed[i] {
			match = false
		}
	}
	if !match {
		return fmt.Errorf("integrity check FAILED: archive has been tampered with")
	}

	fmt.Println("integrity check PASSED")
	return nil
}
