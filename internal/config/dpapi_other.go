// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package config

import "fmt"

// resolveDPAPISecret only exists on Windows: DPAPI is a Windows-only API and
// there is no equivalent this project hand-rolls on Linux. A dpapi: reference
// in a configuration loaded on Linux fails clearly instead of silently
// resolving to nothing.
func resolveDPAPISecret(_ string) (string, error) {
	return "", fmt.Errorf("dpapi: secrets are only supported on Windows; use file: or ${ENV_VAR} on Linux")
}
