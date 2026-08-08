// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package spool

// Windows has no O_NOFOLLOW. Reparse point handling is covered by the data
// directory ACL set by the installer instead.
const noFollow = 0
