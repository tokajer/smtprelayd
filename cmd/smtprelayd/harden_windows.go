// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// hardenProcess restricts every later DLL load to System32
// (docs/dev/EXPLOIT-SURFACE.md section 2). The default search order starts
// with the directory the binary was loaded from and then the current
// directory and PATH, so a DLL planted in any of them whose name matches one
// a system component loads on demand -- the resolver, the certificate store,
// the event log -- runs inside the service. x/sys/windows already loads its
// own DLLs from System32; this covers what those DLLs load in turn, and
// anything the runtime or a dependency loads later.
//
// It runs before flag parsing, so the earliest load it can still affect is
// the first one after main starts. What loads before that is kernel32
// through the import table, a KnownDLL that is never searched for, and the
// DLLs the runtime loads itself, already with LOAD_LIBRARY_SEARCH_SYSTEM32.
func hardenProcess() error {
	if err := windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_SYSTEM32); err != nil {
		return fmt.Errorf("restricting the DLL search path to System32: %w", err)
	}
	return nil
}
