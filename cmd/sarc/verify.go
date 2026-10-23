// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"github.com/iamvirul/sarc/archive"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Check the archive checksum for corruption, without a password",
	Long: "verify recomputes the SHA-256 checksum stored in the archive footer. It detects\n" +
		"accidental corruption (bad disks, truncated transfers) without decrypting anything.\n" +
		"The checksum is not keyed, so it does not prove authenticity: tampering is detected\n" +
		"by extract and list, which authenticate every entry with the archive's keys.",
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVarP(&flagArchive, "archive", "a", "", "archive path, or - for stdin (required)")
	_ = verifyCmd.MarkFlagRequired("archive")
}

// verifyChunkSize is how much of the archive verifyStream reads at a time.
const verifyChunkSize = 1 << 20

var errArchiveTooSmall = errors.New("archive too small to contain a valid footer")

func runVerify(cmd *cobra.Command, args []string) error {
	in, err := openArchiveInput(flagArchive)
	if err != nil {
		return err
	}
	defer in.Close()

	ok, err := verifyStream(in)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("integrity check FAILED: archive checksum mismatch (corrupted or modified)")
	}
	fmt.Println("integrity check PASSED")
	return nil
}

// verifyStream reports whether the archive checksum (see archive.ArchiveChecksum) of
// everything in r before the footer matches the checksum stored in the footer. It reads
// r once without seeking, holding back the last footer-sized bytes, so it works on
// pipes; the comparison is constant time.
func verifyStream(r io.Reader) (bool, error) {
	const footerSize = archive.HMACSize + archive.ReservedSize
	h := archive.NewArchiveChecksum()
	work := make([]byte, footerSize+verifyChunkSize)
	held := 0
	for {
		n, err := r.Read(work[held:])
		held += n
		if held > footerSize {
			h.Write(work[:held-footerSize])
			copy(work, work[held-footerSize:held])
			held = footerSize
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("read archive: %w", err)
		}
	}
	if held < footerSize {
		return false, errArchiveTooSmall
	}
	return subtle.ConstantTimeCompare(h.Sum(nil), work[:archive.HMACSize]) == 1, nil
}
