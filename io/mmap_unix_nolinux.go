// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

//go:build unix && !linux

package io

// mmapPopulateFlag is 0 on non-Linux unix platforms (e.g. Darwin, FreeBSD): MAP_POPULATE
// is a Linux-specific mmap flag with no portable equivalent.
const mmapPopulateFlag = 0
