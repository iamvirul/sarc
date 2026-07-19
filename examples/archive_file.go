// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build ignore

// Example: archive a single file using the streaming archiver.
//
//	go run examples/archive_file.go
package main

import (
	"log"
	"os"

	sarcio "github.com/iamvirul/sarc/io"
)

func main() {
	const (
		password = "example-password-change-me"
		output   = "example.sarc"
	)

	f, err := os.Create(output)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	progress := sarcio.NewConsoleProgressBar(os.Stdout)
	sa, err := sarcio.NewStreamingArchiver(f, password, progress)
	if err != nil {
		log.Fatal(err)
	}

	// Archive this source file itself as a demonstration.
	src := "examples/archive_file.go"
	info, _ := os.Stat(src)
	if err := sa.AddFile(src); err != nil {
		log.Fatal(err)
	}

	if err := sa.Finalize(1, info.Size()); err != nil {
		log.Fatal(err)
	}

	log.Printf("archived to %s", output)
}
