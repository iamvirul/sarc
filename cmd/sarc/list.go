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

	fmt.Printf("%-40s  %-12s  %-11s  %s\n", "FILENAME", "SIZE BUCKET", "CODEC", "RATIO")
	fmt.Printf("%-40s  %-12s  %-11s  %s\n", "--------", "-----------", "-----", "-----")
	for _, r := range results {
		fmt.Printf("%-40s  %-12s  %-11s  %s\n", r.Filename, r.SizeBucket, formatCodec(r), formatRatio(r))
	}
	fmt.Printf("\n%d file(s)\n", len(results))
	return nil
}

// formatCodec renders the codec, marking solid group members, e.g. "zstd+solid".
// A solid member's ratio is its group's ratio.
func formatCodec(r sarcio.ListResult) string {
	if r.Solid {
		return r.Codec + "+solid"
	}
	return r.Codec
}

// minDisplayedRatio is the smallest ratio formatRatio prints exactly; below it "<0.1%".
const minDisplayedRatio = 0.1

// formatRatio renders stored size as a percentage of original size, e.g. "31.4%".
func formatRatio(r sarcio.ListResult) string {
	if r.Err != nil || r.OriginalBytes <= 0 {
		return "-"
	}
	ratio := float64(r.StoredBytes) * 100 / float64(r.OriginalBytes)
	if ratio < minDisplayedRatio {
		return fmt.Sprintf("<%.1f%%", minDisplayedRatio)
	}
	return fmt.Sprintf("%.1f%%", ratio)
}
