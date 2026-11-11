// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package spool

// noFollow is zero on Windows, which has no O_NOFOLLOW. It is not what
// refuses a reparse point there either: openRegular's Lstat reports a
// symlink or junction as such and refuses it before anything is opened.
const noFollow = 0

// noBlock is zero on Windows: a named pipe cannot live in a filesystem
// directory there, so the spool holds nothing an open could block on.
const noBlock = 0
