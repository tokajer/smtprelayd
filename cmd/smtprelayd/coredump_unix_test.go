// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package main

import (
	"syscall"
	"testing"
)

// This lowers the test process's own hard limit, which cannot be raised
// again: the test binary loses core dumps for the rest of the run, which
// costs nothing here, and serve's own tests call disableCoreDumps anyway.
func TestDisableCoreDumpsZeroesBothLimits(t *testing.T) {
	if err := disableCoreDumps(); err != nil {
		t.Fatal(err)
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Cur != 0 || lim.Max != 0 {
		t.Fatalf("RLIMIT_CORE = {%d, %d}, want {0, 0}", lim.Cur, lim.Max)
	}
	// The already-zero path, the one the systemd unit leaves this in.
	if err := disableCoreDumps(); err != nil {
		t.Fatalf("second call: %v", err)
	}
}
