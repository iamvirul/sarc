// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/iamvirul/sarc/archive"
	sarcio "github.com/iamvirul/sarc/io"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List contents of a SARC archive (requires a credential to decrypt filenames)",
	RunE:  runList,
}

func init() {
	addReaderCredentialFlags(listCmd)
	listCmd.Flags().StringVarP(&flagArchive, "archive", "a", "", "archive path, or - for stdin (required)")
	_ = listCmd.MarkFlagRequired("archive")
}

func runList(cmd *cobra.Command, args []string) error {
	opts, err := readerOptions()
	if err != nil {
		return err
	}
	f, err := openArchiveInput(flagArchive)
	if err != nil {
		return err
	}
	defer f.Close()

	ex := sarcio.NewSafeExtractor(f, flagPassword, sarcio.NopProgressTracker{}, append(opts, f.randomAccess()...)...)
	results, err := ex.List()
	if err != nil {
		return err
	}

	fmt.Printf("%-10s  %-40s  %-12s  %-11s  %s\n", "MODE", "FILENAME", "SIZE BUCKET", "CODEC", "RATIO")
	fmt.Printf("%-10s  %-40s  %-12s  %-11s  %s\n", "----", "--------", "-----------", "-----", "-----")
	for _, r := range results {
		if r.Kind != archive.KindRegular {
			fmt.Printf("%-10s  %s\n", formatMode(r.Kind, r.Mode), formatName(r))
			continue
		}
		fmt.Printf("%-10s  %-40s  %-12s  %-11s  %s\n", formatMode(r.Kind, r.Mode), formatName(r), r.SizeBucket, formatCodec(r), formatRatio(r))
	}
	fmt.Printf("\n%d entr%s\n", len(results), map[bool]string{true: "y", false: "ies"}[len(results) == 1])
	return nil
}

// formatName renders an entry's name with its link target: "a -> b" for a symlink and
// "a => b" for a hard link.
func formatName(r sarcio.ListResult) string {
	switch r.Kind {
	case archive.KindSymlink:
		return r.Filename + " -> " + r.LinkTarget
	case archive.KindHardlink:
		return r.Filename + " => " + r.LinkTarget
	}
	return r.Filename
}

// formatMode renders a kind and chmod-form mode as ls -l does, e.g. "drwxr-sr-t".
func formatMode(kind archive.FileKind, mode uint32) string {
	b := []byte("----------")
	switch kind {
	case archive.KindDirectory:
		b[0] = 'd'
	case archive.KindSymlink:
		b[0] = 'l'
	}
	const rwx = "rwxrwxrwx"
	for i := 0; i < 9; i++ {
		if mode&(1<<(8-i)) != 0 {
			b[i+1] = rwx[i]
		}
	}
	special := []struct {
		bit       uint32
		pos       int
		set, lone byte
	}{{0o4000, 3, 's', 'S'}, {0o2000, 6, 's', 'S'}, {0o1000, 9, 't', 'T'}}
	for _, s := range special {
		if mode&s.bit != 0 {
			if b[s.pos] == 'x' {
				b[s.pos] = s.set
			} else {
				b[s.pos] = s.lone
			}
		}
	}
	return string(b)
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
