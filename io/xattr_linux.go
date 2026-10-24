// Copyright (c) 2026 iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license.

package io

import "golang.org/x/sys/unix"

// errNoXattr is the error for a missing extended attribute on Linux.
var errNoXattr = unix.ENODATA
