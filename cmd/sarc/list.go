// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	sarcio "github.com/iamvirul/sarc/io"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List contents of a SARC archive (requires password to decrypt filenames)",
	RunE:  runList,
}

func init() {
	listCmd.Flags().StringVarP(&flagPassword, "password", "p", "", "master password (required)")
	listCmd.Flags().StringVarP(&flagArchive, "archive", "a", "", "archive path (required)")
	_ = listCmd.MarkFlagRequired("password")
	_ = listCmd.MarkFlagRequired("archive")
}

func runList(cmd *cobra.Command, args []string) error {
	f, err := os.Open(flagArchive)
	if err != nil {
		return fmt.Errorf("cannot open archive: %w", err)
	}
	defer f.Close()

	ex := sarcio.NewSafeExtractor(f, flagPassword, sarcio.NopProgressTracker{})
	results, err := ex.List()
	if err != nil {
		return err
	}

	fmt.Printf("%-40s  %s\n", "FILENAME", "SIZE BUCKET")
	fmt.Printf("%-40s  %s\n", "--------", "-----------")
	for _, r := range results {
		fmt.Printf("%-40s  %s\n", r.Filename, r.SizeBucket)
	}
	fmt.Printf("\n%d file(s)\n", len(results))
	return nil
}
