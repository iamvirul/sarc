// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build ignore

// Example: extract all files from a SARC archive.
//
//	go run examples/extract_file.go
package main

import (
	"fmt"
	"log"
	"os"

	sarcio "github.com/iamvirul/sarc/io"
)

func main() {
	const (
		password    = "example-password-change-me"
		archivePath = "example.sarc"
		outputDir   = "./extracted"
	)

	f, err := os.Open(archivePath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	progress := sarcio.NewConsoleProgressBar(os.Stdout)
	ex := sarcio.NewSafeExtractor(f, password, progress)

	results, err := ex.Extract(outputDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, r := range results {
		if r.OK {
			fmt.Printf("extracted: %s (%d bytes)\n", r.Filename, r.Size)
		} else {
			fmt.Printf("failed:    %s: %v\n", r.Filename, r.Err)
		}
	}
}
