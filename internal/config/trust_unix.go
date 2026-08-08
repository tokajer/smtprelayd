// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package config

import (
	"fmt"
	"os"
	"syscall"
)

// CheckConfigFile aborts startup when the configuration could be replaced by
// an unprivileged local user. A writable configuration is a direct path from
// a local account to control of a privileged process, so this is a failure
// and never a warning.
func CheckConfigFile(path string) error {
	return checkTrusted(path, false)
}

// CheckDir applies the same trust requirement to a directory, used for the
// data directory and the directory the binary was started from.
func CheckDir(path string) error {
	return checkTrusted(path, true)
}

func checkSecretFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("secret file %s is a symlink", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("secret file %s is readable by group or others (mode %04o)", path, fi.Mode().Perm())
	}
	return nil
}

func checkTrusted(path string, wantDir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to follow it", path)
	}
	if wantDir != fi.IsDir() {
		return fmt.Errorf("%s: unexpected file type", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot determine ownership", path)
	}
	uid := os.Getuid()
	if int(st.Uid) != 0 && int(st.Uid) != uid {
		return fmt.Errorf("%s is owned by uid %d, expected root or uid %d", path, st.Uid, uid)
	}
	// A group- or world-writable path lets another account swap the contents
	// underneath a privileged process. The sticky bit does not help here
	// because the whole file, not a name inside it, is the target.
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others (mode %04o)", path, fi.Mode().Perm())
	}
	return nil
}
