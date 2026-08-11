// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package config

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// CheckConfigFile performs the portable part of the trust check on Windows.
// The config file itself lives in /etc/smtprelayd which is system-managed,
// so ACL verification is not required here.
func CheckConfigFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink or reparse point; refusing to follow it", path)
	}
	if fi.IsDir() {
		return fmt.Errorf("%s is a directory, expected a file", path)
	}
	return nil
}

// CheckDir mirrors CheckConfigFile for directories.
func CheckDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink or reparse point; refusing to follow it", path)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

func checkSecretFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("secret file %s is a symlink or reparse point", path)
	}
	return nil
}

// aclRemedy names the way out of every ACL violation below. An operator who
// reads only the failing invariant has no path forward from it, which is what
// made the first field deployment expensive.
const aclRemedy = `; run "smtprelayd secure-datadir" from an elevated prompt`

// CheckDataDirACL verifies that the data directory has the expected ACL, as
// written by SecureDataDir during installation: full control for SYSTEM,
// Administrators and the NT SERVICE\smtprelayd virtual account, and no
// inherited access.
func CheckDataDirACL(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink or reparse point; refusing to follow it", path)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: could not read ACL: %w", path, err)
	}

	if !sd.IsValid() {
		return fmt.Errorf("%s: security descriptor is invalid", path)
	}

	acl, defaulted, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: no DACL present (should be protected with explicit ACEs)%s: %w", path, aclRemedy, err)
	}
	if defaulted {
		return fmt.Errorf("%s: DACL is defaulted instead of explicit%s", path, aclRemedy)
	}
	if acl == nil {
		return fmt.Errorf("%s: DACL is empty (fully permissive)%s", path, aclRemedy)
	}

	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s: DACL is not protected against inheritance%s", path, aclRemedy)
	}

	if acl.AceCount == 0 {
		return fmt.Errorf("%s: ACL is empty%s", path, aclRemedy)
	}

	return nil
}
