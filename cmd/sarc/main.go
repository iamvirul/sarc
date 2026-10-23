// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	sarcio "github.com/iamvirul/sarc/io"
)

// Build metadata injected via ldflags at release time.
var (
	version = "dev"
	commit  = "none"
	builtBy = "source"
)

var rootCmd = &cobra.Command{
	Use:     "sarc",
	Short:   "Secure Anti-Deduplication Archive",
	Long:    "sarc creates and extracts AES-256-GCM encrypted archives with anti-deduplication protection.",
	Version: version + " (" + commit + ") built by " + builtBy,
}

func main() {
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	rootCmd.AddCommand(archiveCmd, extractCmd, verifyCmd, listCmd, keygenCmd, signCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, withVolumeDetail(err))
		os.Exit(1)
	}
}

// withVolumeDetail appends the volume that failed to an error caused by a damaged or
// missing volume of a split archive, which an archive error's message alone omits.
func withVolumeDetail(err error) error {
	var ve *sarcio.VolumeError
	if errors.As(err, &ve) && !strings.Contains(err.Error(), ve.Error()) {
		return fmt.Errorf("%v: %w", err, ve)
	}
	return err
}
