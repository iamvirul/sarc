// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"errors"
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
	addReaderCredentialFlags(extractCmd)
	extractCmd.Flags().StringVarP(&flagArchive, "archive", "a", "", "archive path, - for stdin, or a storage URL: "+remoteSchemesHelp+" (required)")
	extractCmd.Flags().StringVarP(&flagOutput, "output", "o", ".", "output directory")
	extractCmd.Flags().BoolVar(&flagDebug, "debug", false, "enable debug logging")
	extractCmd.Flags().BoolVar(&flagPreserveOwner, "preserve-owner", false,
		"restore recorded owners and setuid, setgid, and sticky bits (needs root); otherwise they are skipped with a warning")
	_ = extractCmd.MarkFlagRequired("archive")
}

func runExtract(cmd *cobra.Command, args []string) error {
	log := initLogger()

	if isRemote(flagOutput) {
		return errors.New("extract writes files to a local --output directory, not a storage URL")
	}
	opts, err := readerOptions()
	if err != nil {
		return err
	}
	f, err := openArchiveInput(commandContext(cmd), flagArchive)
	if err != nil {
		return err
	}
	defer f.Close()

	// Progress tracker handles per-file error printing via FileError.
	progress := sarcio.NewConsoleProgressBar(os.Stdout)
	opts = append(opts, f.randomAccess()...)
	if flagPreserveOwner {
		opts = append(opts, sarcio.WithRestoreOwner(true))
	}
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
