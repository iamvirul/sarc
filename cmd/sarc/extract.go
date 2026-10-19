// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	sarcio "github.com/iamvirul/sarc/io"
)

var extractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Decrypt and extract files from a SARC archive",
	RunE:  runExtract,
}

func init() {
	extractCmd.Flags().StringVarP(&flagPassword, "password", "p", "", "archive password")
	extractCmd.Flags().StringArrayVarP(&flagIdentities, "identity", "i", nil, "age identity file (repeatable); an alternative to --password")
	extractCmd.Flags().StringVarP(&flagArchive, "archive", "a", "", "archive path, or - for stdin (required)")
	extractCmd.Flags().StringVarP(&flagOutput, "output", "o", ".", "output directory")
	extractCmd.Flags().BoolVar(&flagDebug, "debug", false, "enable debug logging")
	_ = extractCmd.MarkFlagRequired("archive")
}

func runExtract(cmd *cobra.Command, args []string) error {
	log := initLogger()

	opts, err := readerOptions()
	if err != nil {
		return err
	}
	f, err := openArchiveInput(flagArchive)
	if err != nil {
		return err
	}
	defer f.Close()

	// Progress tracker handles per-file error printing via FileError.
	progress := sarcio.NewConsoleProgressBar(os.Stdout)
	ex := sarcio.NewSafeExtractor(f, flagPassword, progress, opts...)

	results, err := ex.Extract(flagOutput)
	if err != nil {
		return err
	}

	var ok, failed int
	for _, r := range results {
		if r.OK {
			ok++
			log.Debug("extracted", "file", r.Filename, "size", r.Size)
		} else {
			failed++
		}
	}
	fmt.Printf("extracted %d file(s), %d error(s)\n", ok, failed)

	if failed > 0 {
		return fmt.Errorf("%d file(s) failed to extract", failed)
	}
	return nil
}
