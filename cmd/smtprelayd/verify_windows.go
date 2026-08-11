// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/tokajer/smtprelayd/internal/config"
)

// verifyDataDirSecurity checks that the data directory has the ACL set by the
// installer on Windows.
func verifyDataDirSecurity(dataDir string) error {
	return config.CheckDataDirACL(dataDir)
}

// secureDataDir writes that ACL. It runs from the MSI as a deferred custom
// action and from an elevated prompt when an operator has to recover a
// directory whose ACL was lost — never from the running service, which would
// mean a service that widens its own permissions at startup and would defeat
// verifyDataDirSecurity entirely.
//
// The directory is taken from the configuration when one is readable, so a
// relocated data_dir is secured too; at install time no configuration exists
// yet and the location the MSI creates is used.
func secureDataDir(configPath string) error {
	dir := filepath.Dir(configPath)
	if cfg, err := config.Load(configPath); err == nil {
		dir = cfg.Service.DataDir
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := config.SecureDataDir(dir); err != nil {
		return err
	}
	fmt.Printf("smtprelayd: data directory ACL set on %s\n", dir)
	return nil
}
