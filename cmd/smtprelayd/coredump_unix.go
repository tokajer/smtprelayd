// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package main

import (
	"fmt"
	"syscall"
)

// disableCoreDumps sets RLIMIT_CORE to zero, soft and hard, so a crash cannot
// write the OAuth2 client secret or a cached token to disk
// (docs/dev/EXPLOIT-SURFACE.md section 9).
//
// A limit that is already zero is left alone rather than set again: that is
// what the systemd unit's LimitCORE=0 leaves, and the unit's seccomp filter
// should not decide whether the service starts. ~@resources denies the
// setrlimit syscall; Go sets limits through prlimit64, which systemd places
// in @default, so the call is permitted today -- the early return is what
// keeps a filter that ever denies prlimit64 too from failing startup.
func disableCoreDumps() error {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		return fmt.Errorf("core dumps: reading RLIMIT_CORE: %w", err)
	}
	if lim.Cur == 0 && lim.Max == 0 {
		return nil
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return fmt.Errorf("core dumps: setting RLIMIT_CORE to 0 failed (under systemd, set LimitCORE=0 in the unit): %w", err)
	}
	return nil
}
