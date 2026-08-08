// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package main

import "fmt"

// isWindowsService and controlService only do anything on Windows: on Linux
// the service is systemd, managed by the packaged unit file and systemctl,
// not by the binary itself. Keeping kardianos/service out of non-Windows
// builds entirely also keeps its systemd backend, which shells out to
// systemctl, out of the import graph — os/exec is banned, see CLAUDE.md.
func isWindowsService() bool { return false }

func controlService(action, _ string) error {
	return fmt.Errorf("%q is only implemented on Windows; on Linux use: systemctl %s smtprelayd", action, action)
}

func runWindowsService(_ string, _ bool) error {
	return fmt.Errorf("not running as a Windows service host")
}
