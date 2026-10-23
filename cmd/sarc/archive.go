// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"fmt"

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
	archiveCmd.Flags().StringVarP(&flagPassword, "password", "p", "",
		"archive password; with --key, the password and a key file are both required")
	archiveCmd.Flags().StringArrayVarP(&flagKeyFiles, "key", "k", nil,
		"key file (32 bytes to 1 MiB, e.g. from sarc keygen --keyfile) that opens the archive (repeatable)")
	archiveCmd.Flags().StringArrayVarP(&flagRecipients, "recipient", "r", nil,
		"public key allowed to open the archive: age (age1...), SSH (ssh-ed25519, ssh-rsa), or plugin such as age1yubikey1..., or a file of them (repeatable)")
	archiveCmd.Flags().StringArrayVarP(&flagIdentities, "identity", "i", nil,
		"identity file (age, SSH, or plugin) whose holder can open the archive (repeatable); only its public key is used")
	archiveCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "output archive path, or - for stdout (required)")
	archiveCmd.Flags().IntVar(&flagParallel, "parallel", 0, "worker count (default: NumCPU)")
	archiveCmd.Flags().BoolVar(&flagDebug, "debug", false, "enable debug logging")
	archiveCmd.Flags().BoolVar(&flagCompress, "compress", false, "zstd-compress every file (default: auto, skips incompressible files)")
	archiveCmd.Flags().BoolVar(&flagNoCompress, "no-compress", false, "store every file uncompressed")
	archiveCmd.Flags().IntVar(&flagCompressLevel, "compress-level", archive.DefaultCompressionLevel,
		fmt.Sprintf("zstd compression level %d-%d", archive.MinCompressionLevel, archive.MaxCompressionLevel))
	archiveCmd.Flags().BoolVar(&flagSolid, "solid", false,
		"pack files up to 1 MiB into shared solid groups compressed as one stream (smaller archives of many small files; one key per group instead of per file)")
	archiveCmd.Flags().BoolVar(&flagIncremental, "incremental", false,
		"create the archive at --output, or add a session to it: only new or changed data is written, deleted files are recorded")
	archiveCmd.MarkFlagsMutuallyExclusive("compress", "no-compress")
	archiveCmd.MarkFlagsMutuallyExclusive("incremental", "solid")
	_ = archiveCmd.MarkFlagRequired("output")
}

func runArchive(cmd *cobra.Command, args []string) error {
	log := initLogger()

	password, credentialOpts, err := archiveCredentials()
	if err != nil {
		return err
	}
	compression, err := compressionOptions(cmd)
	if err != nil {
		return err
	}
	log.Debug("compression", "mode", compression.Mode.String(), "level", compression.Level, "solid", compression.Solid)
	if flagIncremental {
		return runIncremental(cmd, args, password, append(credentialOpts, sarcio.WithCompression(compression)))
	}

	out, err := createArchiveOutput(flagOutput)
	if err != nil {
		return err
	}
	defer out.Close()

	totalFiles, totalInputBytes := sarcio.InputTotals(args)
	if out.file != nil {
		if err := sarcio.PreallocateOutput(out.file, totalInputBytes); err != nil {
			log.Debug("preallocate output file skipped", "err", err)
		}
	}

	progress := sarcio.NewConsoleProgressBar(out.progress)

	if flagParallel != 1 {
		log.Debug("using concurrent archiver", "workers", flagParallel)
		ca, err := sarcio.NewConcurrentArchiver(out, password, flagParallel, progress,
			append(credentialOpts, sarcio.WithCompression(compression))...)
		if err != nil {
			return err
		}
		return ca.Archive(args)
	}

	log.Debug("using streaming archiver")
	sa, err := sarcio.NewStreamingArchiver(out, password, progress,
		append(credentialOpts, sarcio.WithCompression(compression))...)
	if err != nil {
		return err
	}
	for _, path := range args {
		if err := sa.AddFile(path); err != nil {
			log.Error("file failed", "path", path, "err", err)
		}
	}
	return sa.Finalize(totalFiles, totalInputBytes)
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
