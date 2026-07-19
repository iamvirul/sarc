// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// ProgressTracker receives progress events during archive and extract operations.
type ProgressTracker interface {
	// FileStarted is called when a file begins processing.
	FileStarted(name string, sizeBytes int64)
	// BytesProcessed is called after each chunk is written or read.
	BytesProcessed(n int64)
	// FileFinished is called when a file completes successfully.
	FileFinished(name string)
	// FileError is called when a file fails. Processing may continue for other files.
	FileError(name string, err error)
	// Done is called once when all files have been processed.
	Done(totalFiles int, totalBytes int64, elapsed time.Duration)
}

// Metrics holds counters updated atomically during processing.
type Metrics struct {
	FilesProcessed atomic.Int64
	FilesErrored   atomic.Int64
	BytesProcessed atomic.Int64
}

// ConsoleProgressBar writes human-readable progress to an io.Writer.
type ConsoleProgressBar struct {
	w       io.Writer
	metrics *Metrics
	start   time.Time
}

// NewConsoleProgressBar returns a ConsoleProgressBar writing to w.
func NewConsoleProgressBar(w io.Writer) *ConsoleProgressBar {
	return &ConsoleProgressBar{w: w, metrics: &Metrics{}, start: time.Now()}
}

// Metrics returns the live counters.
func (pb *ConsoleProgressBar) Metrics() *Metrics { return pb.metrics }

func (pb *ConsoleProgressBar) FileStarted(name string, sizeBytes int64) {
	fmt.Fprintf(pb.w, "  -> %s (%s)\n", name, formatBytes(sizeBytes))
}

func (pb *ConsoleProgressBar) BytesProcessed(n int64) {
	pb.metrics.BytesProcessed.Add(n)
}

func (pb *ConsoleProgressBar) FileFinished(name string) {
	pb.metrics.FilesProcessed.Add(1)
}

func (pb *ConsoleProgressBar) FileError(name string, err error) {
	pb.metrics.FilesErrored.Add(1)
	fmt.Fprintf(pb.w, "  ERROR %s: %v\n", name, err)
}

func (pb *ConsoleProgressBar) Done(totalFiles int, totalBytes int64, elapsed time.Duration) {
	throughput := float64(totalBytes) / elapsed.Seconds() / (1024 * 1024)
	fmt.Fprintf(pb.w, "done: %d file(s), %s in %.2fs (%.0f MB/s)\n",
		totalFiles, formatBytes(totalBytes), elapsed.Seconds(), throughput)
}

// NopProgressTracker discards all progress events.
type NopProgressTracker struct{}

func (NopProgressTracker) FileStarted(_ string, _ int64)        {}
func (NopProgressTracker) BytesProcessed(_ int64)               {}
func (NopProgressTracker) FileFinished(_ string)                {}
func (NopProgressTracker) FileError(_ string, _ error)          {}
func (NopProgressTracker) Done(_ int, _ int64, _ time.Duration) {}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.2f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
