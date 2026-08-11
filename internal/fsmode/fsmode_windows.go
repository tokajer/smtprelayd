// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package fsmode

// restrictFile is a no-op on Windows, for the same reason spool.ensureMode
// is: os.Chmod only toggles the read-only attribute there, so it would
// enforce nothing while still being able to fail on a file whose DACL denies
// WRITE_ATTRIBUTES. Access to everything under the data directory is
// governed by the DACL the installer writes and CheckDataDirACL verifies.
func restrictFile(string) error { return nil }
