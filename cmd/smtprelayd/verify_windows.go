// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"github.com/tokajer/smtprelayd/internal/config"
)

// verifyDataDirSecurity checks that the data directory has the ACL set by the
// installer on Windows.
func verifyDataDirSecurity(dataDir string) error {
	return config.CheckDataDirACL(dataDir)
}
