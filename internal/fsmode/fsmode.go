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

// ShareWithGroupOf gives path the group that owns reference, and the least
// permissive mode that still lets that group read it: 0750 for a directory,
// 0640 for a file.
//
// It exists because a file the operator creates by hand is owned by whoever
// ran the command — root, on a server — while the service runs as its own
// unprivileged account. A private key written 0600 root:root inside a 0700
// directory is one the service cannot open, and the failure surfaces as a
// service that will not start rather than as anything about permissions.
// Passing the configuration file as reference picks up whatever group the
// package assigned (root:smtprelayd on Linux), so no account name has to be
// hardcoded here.
//
// It returns the group it applied, so the caller can say which one. That
// matters: the reference is whatever group the operator's configuration file
// happens to carry, and on a hand-made install that can be a shared group
// every local account belongs to. Widening a private key to it is not
// something to do silently.
//
// On Windows it is a no-op and returns an empty name, for the reason
// RestrictFile is: access there is governed by the inherited DACL, not by
// mode bits or a POSIX group.
func ShareWithGroupOf(path, reference string) (string, error) {
	return shareWithGroupOf(path, reference)
}
