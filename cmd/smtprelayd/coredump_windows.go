// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"fmt"
	"os"
)

// disableCoreDumps refuses to start when GOTRACEBACK asks the runtime to hand
// a crash to Windows Error Reporting (docs/dev/EXPLOIT-SURFACE.md section 9).
//
// Windows has no RLIMIT_CORE, and a process cannot opt out of WER's
// LocalDumps through a limit -- but the Go runtime already keeps WER out:
// it sets SEM_NOGPFAULTERRORBOX and WER_FAULT_REPORTING_NO_UI at startup and
// ends a fatal error by exiting, not by raising it to the OS. It raises one
// only when the traceback level carries the crash flag, and runtime
// setTraceback sets that for exactly two values, "crash" and "wer", compared
// as written; every other value, numeric ones included, leaves it clear. A
// dump WER wrote then would hold the OAuth2 client secret and any cached
// token in plain text.
//
// That makes the environment the whole control. Everything else that can
// dump the running process -- procdump, Task Manager, a debugger -- has to
// open it with PROCESS_VM_READ, which for a service account's process needs
// administrator rights, and an administrator is conceded by the threat model
// already: one can read the secret through DPAPI directly.
func disableCoreDumps() error {
	return checkTraceback(os.Getenv("GOTRACEBACK"))
}

func checkTraceback(level string) error {
	switch level {
	case "crash", "wer":
		return fmt.Errorf("core dumps: GOTRACEBACK=%s makes a crash write a dump holding the client secret; "+
			"remove GOTRACEBACK from the service's environment (the Environment value under "+
			`HKLM\SYSTEM\CurrentControlSet\Services\smtprelayd, or the system environment)`, level)
	}
	return nil
}
