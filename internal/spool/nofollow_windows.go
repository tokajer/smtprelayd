// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package spool

// noFollow is zero on Windows, which has no O_NOFOLLOW. Reparse point
// handling is covered by the data directory ACL the installer sets instead.
const noFollow = 0
