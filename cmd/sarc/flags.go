// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"log/slog"
	"os"
)

var (
	flagPassword string
	flagOutput   string
	flagArchive  string
	flagParallel int
	flagDebug    bool
)

// initLogger configures the global structured logger.
// Debug level is only enabled when --debug is passed; never in production by default.
func initLogger() *slog.Logger {
	level := slog.LevelInfo
	if flagDebug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
