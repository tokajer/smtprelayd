// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package main

// verifyDataDirSecurity is a no-op on Unix, where directory permissions are
// checked by CheckDir instead.
func verifyDataDirSecurity(dataDir string) error {
	return nil
}
