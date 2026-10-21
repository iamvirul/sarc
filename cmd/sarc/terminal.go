// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"fmt"
	"os"
	"runtime"

	"filippo.io/age/plugin"
	"golang.org/x/term"
)

// pluginUI returns the interface age plugins use to talk to the user (for example
// "touch your YubiKey" or a PIN prompt). Messages go to stderr and input is read from
// the terminal directly, so neither collides with an archive on stdin or stdout.
func pluginUI() *plugin.ClientUI {
	return plugin.NewTerminalUI(
		func(format string, v ...any) { fmt.Fprintf(os.Stderr, "sarc: "+format+"\n", v...) },
		func(format string, v ...any) { fmt.Fprintf(os.Stderr, "sarc: warning: "+format+"\n", v...) },
	)
}

// readSecret prompts on the controlling terminal and reads a line without echo,
// bypassing stdin and stdout so it works while an archive is piped.
func readSecret(prompt string) ([]byte, error) {
	in, out, err := openTerminal()
	if err != nil {
		return nil, fmt.Errorf("a terminal is required to read a passphrase: %w", err)
	}
	defer in.Close()
	if out != in {
		defer out.Close()
	}
	fmt.Fprint(out, prompt+" ")
	secret, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return secret, nil
}

// openTerminal opens the console for input and output: /dev/tty on Unix, CONIN$ and
// CONOUT$ on Windows.
func openTerminal() (in, out *os.File, err error) {
	if runtime.GOOS != "windows" {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		return tty, tty, err
	}
	in, err = os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	out, err = os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		in.Close()
		return nil, nil, err
	}
	return in, out, nil
}
