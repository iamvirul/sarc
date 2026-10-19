// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/iamvirul/sarc/archive"
	sarcio "github.com/iamvirul/sarc/io"
)

var archiveCmd = &cobra.Command{
	Use:   "archive [files...]",
	Short: "Create a SARC archive",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runArchive,
}

func init() {
	archiveCmd.Flags().StringVarP(&flagPassword, "password", "p", "", "archive password")
	archiveCmd.Flags().StringArrayVarP(&flagRecipients, "recipient", "r", nil,
		"age public key (age1...) or recipients file allowed to decrypt (repeatable); any one recipient or the password can open the archive")
	archiveCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "output archive path (required)")
	archiveCmd.Flags().IntVar(&flagParallel, "parallel", 0, "worker count (default: NumCPU)")
	archiveCmd.Flags().BoolVar(&flagDebug, "debug", false, "enable debug logging")
	archiveCmd.Flags().BoolVar(&flagCompress, "compress", false, "zstd-compress every file (default: auto, skips incompressible files)")
	archiveCmd.Flags().BoolVar(&flagNoCompress, "no-compress", false, "store every file uncompressed")
	archiveCmd.Flags().IntVar(&flagCompressLevel, "compress-level", archive.DefaultCompressionLevel,
		fmt.Sprintf("zstd compression level %d-%d", archive.MinCompressionLevel, archive.MaxCompressionLevel))
	archiveCmd.Flags().BoolVar(&flagSolid, "solid", false,
		"pack files up to 1 MiB into shared solid groups compressed as one stream (smaller archives of many small files; one key per group instead of per file)")
	archiveCmd.MarkFlagsMutuallyExclusive("compress", "no-compress")
	_ = archiveCmd.MarkFlagRequired("output")
}

func runArchive(cmd *cobra.Command, args []string) error {
	log := initLogger()

	if flagPassword == "" && len(flagRecipients) == 0 {
		return errNoCredential
	}
	if flagPassword != "" {
		if err := validatePassword(flagPassword); err != nil {
			return err
		}
	}
	recipients, err := parseRecipients(flagRecipients)
	if err != nil {
		return err
	}
	compression, err := compressionOptions(cmd)
	if err != nil {
		return err
	}
	log.Debug("compression", "mode", compression.Mode.String(), "level", compression.Level, "solid", compression.Solid)

	f, err := os.Create(flagOutput)
	if err != nil {
		return fmt.Errorf("cannot create output file: %w", err)
	}
	defer f.Close()

	var totalInputBytes int64
	for _, path := range args {
		if info, statErr := os.Stat(path); statErr == nil {
			totalInputBytes += info.Size()
		}
	}
	if err := sarcio.PreallocateOutput(f, totalInputBytes); err != nil {
		log.Debug("preallocate output file skipped", "err", err)
	}

	progress := sarcio.NewConsoleProgressBar(os.Stdout)

	if flagParallel != 1 {
		log.Debug("using concurrent archiver", "workers", flagParallel)
		ca, err := sarcio.NewConcurrentArchiver(f, flagPassword, flagParallel, progress,
			sarcio.WithCompression(compression), sarcio.WithAgeRecipients(recipients...))
		if err != nil {
			return err
		}
		return ca.Archive(args)
	}

	log.Debug("using streaming archiver")
	sa, err := sarcio.NewStreamingArchiver(f, flagPassword, progress,
		sarcio.WithCompression(compression), sarcio.WithAgeRecipients(recipients...))
	if err != nil {
		return err
	}
	for _, path := range args {
		if err := sa.AddFile(path); err != nil {
			log.Error("file failed", "path", path, "err", err)
		}
	}
	return sa.Finalize(len(args), totalInputBytes)
}

// compressionOptions maps the compression flags to archiver options, rejecting
// out-of-range levels and a level given alongside --no-compress.
func compressionOptions(cmd *cobra.Command) (sarcio.CompressionOptions, error) {
	if flagCompressLevel < archive.MinCompressionLevel || flagCompressLevel > archive.MaxCompressionLevel {
		return sarcio.CompressionOptions{}, fmt.Errorf("--compress-level must be between %d and %d",
			archive.MinCompressionLevel, archive.MaxCompressionLevel)
	}
	if flagNoCompress && cmd.Flags().Changed("compress-level") {
		return sarcio.CompressionOptions{}, fmt.Errorf("--compress-level cannot be used with --no-compress")
	}
	opts := sarcio.CompressionOptions{Mode: sarcio.CompressionAuto, Level: flagCompressLevel, Solid: flagSolid}
	switch {
	case flagCompress:
		opts.Mode = sarcio.CompressionAlways
	case flagNoCompress:
		opts.Mode = sarcio.CompressionNever
	}
	return opts, nil
}

func validatePassword(p string) error {
	if len(p) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	return nil
}
