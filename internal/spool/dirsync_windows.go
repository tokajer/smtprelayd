// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package spool

// syncDir is a no-op on Windows. FlushFileBuffers requires a handle opened
// with GENERIC_WRITE, which cannot be obtained for a directory, so the call
// can only ever fail -- with ERROR_ACCESS_DENIED in practice, not the
// ERROR_INVALID_HANDLE the previous implementation tried to filter on.
// Metadata and body files are individually fsynced before the rename, and
// NTFS journals the rename itself, so the durability this provides on Unix is
// already covered by the filesystem here.
func syncDir(string) error { return nil }

// ensureMode is a no-op on Windows. Unix mode bits do not restrict access
// there -- os.Chmod only toggles the read-only attribute -- and access is
// governed by the data directory's explicit DACL, which the installer sets
// and CheckDataDirACL verifies at startup.
func ensureMode(string) error { return nil }
