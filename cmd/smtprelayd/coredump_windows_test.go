// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"strings"
	"testing"
)

// GOTRACEBACK=crash or wer is the only way a Go process on Windows hands a
// crash to WER, whose LocalDumps would then write the client secret to disk.
// Every other value the runtime parses leaves that off and must still start.
func TestDisableCoreDumpsRefusesACrashingTraceback(t *testing.T) {
	for _, level := range []string{"crash", "wer"} {
		t.Setenv("GOTRACEBACK", level)
		err := disableCoreDumps()
		if err == nil {
			t.Errorf("GOTRACEBACK=%s was accepted", level)
			continue
		}
		if !strings.Contains(err.Error(), "GOTRACEBACK") || !strings.Contains(err.Error(), "remove") {
			t.Errorf("GOTRACEBACK=%s: the error does not name the variable and the fix: %v", level, err)
		}
	}
	// The runtime compares as written, so these do not set the crash flag
	// either and refusing them would only be noise.
	for _, level := range []string{"", "none", "single", "all", "system", "0", "2", "Crash", "crash,"} {
		t.Setenv("GOTRACEBACK", level)
		if err := disableCoreDumps(); err != nil {
			t.Errorf("GOTRACEBACK=%q was refused: %v", level, err)
		}
	}
}
