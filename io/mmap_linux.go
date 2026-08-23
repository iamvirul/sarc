// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build linux

package io

import "golang.org/x/sys/unix"

// mmapPopulateFlag prefaults pages at mmap time so the kernel can read ahead while the
// first blocks are being encrypted, instead of taking a page fault per 4 KB page on
// first touch. Linux-only: MAP_POPULATE has no equivalent on other unix platforms.
const mmapPopulateFlag = unix.MAP_POPULATE
