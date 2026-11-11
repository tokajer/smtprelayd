// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package main

// hardenProcess has nothing to do outside Windows: the release binary is
// built with CGO_ENABLED=0 and is static, so it loads no shared objects and
// there is no search path to restrict.
func hardenProcess() error { return nil }
