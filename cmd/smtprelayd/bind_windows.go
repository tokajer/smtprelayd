// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isAddrInUse reports whether err is "address already in use". Winsock uses
// its own code for that: a different number from the syscall package's
// EADDRINUSE, which does not compare equal to it.
func isAddrInUse(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE)
}
