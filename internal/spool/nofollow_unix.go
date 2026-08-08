// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package spool

import "syscall"

// noFollow prevents a symlink planted in the spool from redirecting a write
// to a file the service account should not be touching.
const noFollow = syscall.O_NOFOLLOW
