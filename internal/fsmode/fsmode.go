// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package fsmode restricts files the service creates through code that does
// not let the caller choose a mode. The spool opens its own files with
// O_EXCL and 0600 and needs none of this; the history database and the log
// file are created by the SQLite driver and by lumberjack respectively, both
// of which default to 0644, and both of which hold every sender, recipient
// and subject that passed through the relay.
package fsmode

// RestrictFile makes path readable and writable only by its owner. On
// Windows it is a no-op: mode bits do not govern access there, and the data
// directory's explicit DACL does — see CheckDataDirACL.
//
// A path that does not exist is not an error. The callers use this on files
// their dependency may or may not have created yet (a WAL sidecar, a log
// file on a fresh install), and a missing file is nothing to restrict.
func RestrictFile(path string) error { return restrictFile(path) }
