// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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
	rootCmd.AddCommand(archiveCmd, extractCmd, verifyCmd, listCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
