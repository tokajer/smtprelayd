// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package main

import "fmt"

// verifyDataDirSecurity is a no-op on Unix, where directory permissions are
// checked by CheckDir instead.
func verifyDataDirSecurity(dataDir string) error {
	return nil
}

func secureDataDir(_ string) error {
	return fmt.Errorf("secure-datadir is only implemented on Windows; on Linux the data directory is owned by the smtprelayd user with mode 0700, set by the package postinstall")
}

func purgeDataDir(_ string) error {
	return fmt.Errorf("purge-datadir is only implemented on Windows, driven by the MSI's uninstall dialog; on Linux the data directory is left in place by `dnf remove`/`apt purge` deliberately and an operator removes it by hand if they want it gone")
}
