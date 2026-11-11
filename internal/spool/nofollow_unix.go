// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package spool

import "syscall"

// noFollow is passed on every open in the spool. It is not what refuses a
// planted symlink: os.Root opens every component with O_NOFOLLOW already and
// then resolves a symlink that stays inside the root itself, so that refusal
// is openRegular's, and O_CREATE|O_EXCL under a root never follows one. It is
// kept so the flag set says what each open intends.
const noFollow = syscall.O_NOFOLLOW

// noBlock is on openRegular's read open: a FIFO swapped in between its
// Lstat and the open would otherwise block that open, and with it the
// caller, until a writer appeared. It changes nothing for a regular file.
const noBlock = syscall.O_NONBLOCK
