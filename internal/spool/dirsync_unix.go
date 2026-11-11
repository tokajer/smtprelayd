// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package spool

import "os"

// syncDir flushes dir, one of the spool subdirectories, so that a rename
// into it survives a power loss. Errors are propagated: on Unix a failed
// directory fsync means the rename may not be durable, which is exactly the
// guarantee the spool sells.
func syncDir(root *os.Root, dir string) error {
	d, err := root.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ensureMode restricts a spool directory to its owner. The mode bits are the
// enforcement mechanism here, so a failure is fatal.
func ensureMode(path string) error {
	//#nosec G302 -- a directory needs its execute bit; 0700 is the restrictive mode here, not a lax one
	return os.Chmod(path, 0o700)
}
