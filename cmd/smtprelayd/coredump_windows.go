// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

// disableCoreDumps is a no-op on Windows, which has no RLIMIT_CORE. Crash
// dumps there are written by Windows Error Reporting, which a process cannot
// opt out of through a resource limit; nothing here configures it.
func disableCoreDumps() error { return nil }
