// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

// purgeDataDir removes the data directory entirely: the spool and the
// history database. It runs from the MSI as a deferred custom action,
// scheduled only when the operator answered "yes" to the uninstall dialog
// asking whether to also delete %ProgramData%\SMTPRelayd — the MSI does not
// remove it by default, since the spool may still hold accepted, undelivered
// mail; this is the explicit, opt-in path for an operator who wants it gone.
//
// dir is resolved exactly like secureDataDir's: the configured data_dir when
// the configuration still loads, the config file's own directory otherwise.
// Unlike secureDataDir, a resolved directory whose last path element is not
// "SMTPRelayd" is refused rather than acted on: this deletes recursively and
// runs unattended from a deferred custom action with no further
// confirmation, so a wrong resolution here must fail closed rather than
// remove whatever it computed.
func purgeDataDir(configPath string) error {
	dir := filepath.Dir(configPath)
	if cfg, err := config.Load(configPath); err == nil {
		dir = cfg.Service.DataDir
	}
	if !filepath.IsAbs(dir) || !strings.EqualFold(filepath.Base(dir), "SMTPRelayd") {
		return fmt.Errorf("refusing to remove %q: does not look like the smtprelayd data directory", dir)
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	fmt.Printf("smtprelayd: data directory removed: %s\n", dir)
	return nil
}
