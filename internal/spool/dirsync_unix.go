// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package spool

import "os"

// syncDir flushes a directory entry so that a rename survives a power loss.
// Errors are propagated: on Unix a failed directory fsync means the rename
// may not be durable, which is exactly the guarantee the spool sells.
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ensureMode restricts a spool directory to its owner. The mode bits are the
// enforcement mechanism here, so a failure is fatal.
func ensureMode(path string) error {
	return os.Chmod(path, 0o700)
}
