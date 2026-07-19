// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	sarcio "github.com/iamvirul/sarc/io"
)

var archiveCmd = &cobra.Command{
	Use:   "archive [files...]",
	Short: "Create a SARC archive",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runArchive,
}

func init() {
	archiveCmd.Flags().StringVarP(&flagPassword, "password", "p", "", "master password (required)")
	archiveCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "output archive path (required)")
	archiveCmd.Flags().IntVar(&flagParallel, "parallel", 0, "worker count (default: NumCPU)")
	archiveCmd.Flags().BoolVar(&flagDebug, "debug", false, "enable debug logging")
	_ = archiveCmd.MarkFlagRequired("password")
	_ = archiveCmd.MarkFlagRequired("output")
}

func runArchive(cmd *cobra.Command, args []string) error {
	log := initLogger()

	if err := validatePassword(flagPassword); err != nil {
		return err
	}

	f, err := os.Create(flagOutput)
	if err != nil {
		return fmt.Errorf("cannot create output file: %w", err)
	}
	defer f.Close()

	progress := sarcio.NewConsoleProgressBar(os.Stdout)

	if flagParallel != 1 {
		log.Debug("using concurrent archiver", "workers", flagParallel)
		ca, err := sarcio.NewConcurrentArchiver(f, flagPassword, flagParallel, progress)
		if err != nil {
			return err
		}
		return ca.Archive(args)
	}

	log.Debug("using streaming archiver")
	sa, err := sarcio.NewStreamingArchiver(f, flagPassword, progress)
	if err != nil {
		return err
	}
	var totalBytes int64
	for _, path := range args {
		info, statErr := os.Stat(path)
		if statErr == nil {
			totalBytes += info.Size()
		}
		if err := sa.AddFile(path); err != nil {
			log.Error("file failed", "path", path, "err", err)
		}
	}
	return sa.Finalize(len(args), totalBytes)
}

func validatePassword(p string) error {
	if len(p) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	return nil
}
