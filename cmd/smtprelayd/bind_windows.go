// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// Winsock reports its own code here. It is a different number from the
// syscall package's EADDRINUSE and does not compare equal to it.
func isAddrInUse(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE)
}
