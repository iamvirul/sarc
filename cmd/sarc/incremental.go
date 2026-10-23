// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	sarcio "github.com/iamvirul/sarc/io"
)

// runIncremental creates or updates the incremental archive at --output. password and
// opts protect a new archive; the raw credential flags open an existing one.
func runIncremental(cmd *cobra.Command, args []string, password string, opts []sarcio.ArchiverOption) error {
	if flagOutput == stdioPath {
		return errors.New("--incremental needs an archive file for --output, not stdout")
	}
	keys, err := readKeyFiles(flagKeyFiles)
	if err != nil {
		return err
	}
	identities, err := loadIdentities(flagIdentities)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	res, err := sarcio.ArchiveIncremental(flagOutput, args, sarcio.IncrementalOptions{
		Password:       password,
		UnlockPassword: flagPassword,
		KeyFiles:       keys,
		Identities:     identities,
		Archiver:       opts,
		Progress:       sarcio.NewConsoleProgressBar(out),
	})
	if err != nil {
		return err
	}
	printIncrementalResult(out, res)
	if res.SignatureRemoved {
		fmt.Fprintln(cmd.ErrOrStderr(), "note: the archive changed, so its signature was removed; sign it again with sarc sign or --sign")
	}
	if !res.Created && len(flagRecipients) > 0 {
		fmt.Fprintln(cmd.ErrOrStderr(), "note: --recipient was ignored; recipients are fixed when an incremental archive is created")
	}
	if res.Failed > 0 {
		return fmt.Errorf("%d file(s) could not be read; their previous versions were kept", res.Failed)
	}
	return nil
}

func printIncrementalResult(w io.Writer, res sarcio.IncrementalResult) {
	if res.Repaired {
		fmt.Fprintln(w, "repaired the end of the archive after an interrupted update")
	}
	switch {
	case res.Created:
		fmt.Fprintf(w, "created incremental archive: session 1, %d file(s) (%s), %d chunk(s), %s written\n",
			res.Changed, sarcio.FormatBytes(res.ChangedBytes), res.NewChunks, sarcio.FormatBytes(res.AppendedBytes))
	case res.Changed == 0 && res.Deleted == 0 && res.Signed:
		fmt.Fprintf(w, "no changes since session %d (%d file(s) unchanged); archive signed\n", res.Session, res.Unchanged)
		return
	case res.Changed == 0 && res.Deleted == 0:
		fmt.Fprintf(w, "no changes since session %d; archive not modified (%d file(s) unchanged)\n", res.Session, res.Unchanged)
	default:
		fmt.Fprintf(w, "session %d: %d file(s) changed (%s), %d unchanged, %d deleted; appended %s in %d new chunk(s)\n",
			res.Session, res.Changed, sarcio.FormatBytes(res.ChangedBytes), res.Unchanged, res.Deleted,
			sarcio.FormatBytes(res.AppendedBytes), res.NewChunks)
	}
	if res.Signed {
		fmt.Fprintln(w, "archive signed")
	}
}
