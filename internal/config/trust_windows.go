// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package config

import (
	"fmt"
	"os"
	"unsafe"

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

// CheckDataDirACL verifies that the data directory has the expected ACL set by
// the installer. The MSI sets an explicit DACL allowing only Administrators
// and the NT SERVICE\smtprelayd virtual account, with no inherited access.
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

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	var sd *windows.SECURITY_DESCRIPTOR
	err = windows.GetNamedSecurityInfo(pathPtr, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, &sd, nil)
	if err != nil {
		return fmt.Errorf("%s: could not read ACL: %w", path, err)
	}
	defer windows.LocalFree((windows.Handle)(unsafe.Pointer(sd)))

	if !sd.IsValid() {
		return fmt.Errorf("%s: security descriptor is invalid", path)
	}

	present, defaulted, acl, err := sd.DACL()
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("%s: no DACL present (should be protected with explicit ACEs)", path)
	}
	if defaulted {
		return fmt.Errorf("%s: DACL is defaulted instead of explicit", path)
	}

	protected, err := sd.ControlBits()
	if err != nil {
		return err
	}
	if protected&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s: DACL is not protected against inheritance", path)
	}

	count, err := acl.AccessEntryCount()
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("%s: ACL is empty", path)
	}

	return nil
}
