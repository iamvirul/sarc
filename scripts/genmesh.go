// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build ignore

// genmesh writes a synthetic binary STL mesh file: an 80-byte header, a
// uint32 triangle count, then packed float32 normals/vertices and a uint16
// attribute byte count per triangle (the standard binary STL layout). Used
// by the benchmark workflow to produce a 3D-mesh-shaped payload for the
// sarc vs zip comparison, in addition to opaque random data.
//
//	go run scripts/genmesh.go <output-path> <size-mb>
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"strconv"
)

const triangleSize = 50 // 12 float32 (normal + 3 vertices) + uint16 attribute count

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: genmesh <output-path> <size-mb>")
		os.Exit(1)
	}
	path := os.Args[1]
	sizeMB, err := strconv.Atoi(os.Args[2])
	if err != nil || sizeMB <= 0 {
		fmt.Fprintln(os.Stderr, "size-mb must be a positive integer")
		os.Exit(1)
	}

	targetBytes := int64(sizeMB) * 1024 * 1024
	triangleCount := int((targetBytes - 84) / triangleSize)
	if triangleCount < 1 {
		triangleCount = 1
	}

	if err := writeMesh(path, triangleCount); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s: %d triangles (~%d MB)\n", path, triangleCount, sizeMB)
}

func writeMesh(path string, triangleCount int) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 1<<20)

	header := make([]byte, 80)
	for i := range header {
		header[i] = 0xAB
	}
	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	countBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(countBuf, uint32(triangleCount))
	if _, err := w.Write(countBuf); err != nil {
		return fmt.Errorf("write triangle count: %w", err)
	}

	tri := make([]byte, triangleSize)
	for i := 0; i < triangleCount; i++ {
		vals := [12]float32{
			0, 0, 1,
			float32(i), float32(i) + 1, float32(i) + 2,
			float32(i) + 3, float32(i) + 4, float32(i) + 5,
			float32(i) + 6, float32(i) + 7, float32(i) + 8,
		}
		for j, v := range vals {
			binary.LittleEndian.PutUint32(tri[j*4:], math.Float32bits(v))
		}
		binary.LittleEndian.PutUint16(tri[48:], 0)
		if _, err := w.Write(tri); err != nil {
			return fmt.Errorf("write triangle %d: %w", i, err)
		}
	}

	return w.Flush()
}
