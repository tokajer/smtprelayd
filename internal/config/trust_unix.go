// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// CheckConfigFile aborts startup when the configuration could be replaced by
// an unprivileged local user. A writable configuration is a direct path from
// a local account to control of a privileged process, so this is a failure
// and never a warning.
func CheckConfigFile(path string) error {
	if err := checkTrusted(path, false); err != nil {
		return err
	}
	// Also check the directory holding the file, since a writable directory
	// allows an attacker to replace the file via unlink and create.
	dir := filepath.Dir(path)
	return checkTrusted(dir, true)
}

// CheckDir applies the same trust requirement to a directory, used for the
// data directory and the directory the binary was started from.
func CheckDir(path string) error {
	return checkTrusted(path, true)
}

// checkSecretFile applies the config file's trust requirement to a file
// named by a "file:" secret reference, plus a mode check the configuration
// file does not need: a secret must not be readable by group or others.
//
// Like CheckConfigFile it also checks the directory holding the file, because
// ownership of the file alone does not prevent the unlink-and-create
// replacement that a writable parent allows — which is the same attack
// CheckConfigFile was fixed for on 2026-08-10, and the reason this function
// having been left behind was a finding. Both stop at the immediate parent:
// an attacker who controls a higher ancestor can rename the whole subtree,
// and that is not defended against here.
func checkSecretFile(path string) error {
	if err := checkTrusted(filepath.Dir(path), true); err != nil {
		return fmt.Errorf("directory of secret file %s: %w", path, err)
	}

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
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot determine ownership", path)
	}
	uid := os.Getuid()
	if int(st.Uid) != 0 && int(st.Uid) != uid {
		return fmt.Errorf("secret file %s is owned by uid %d, expected root or uid %d", path, st.Uid, uid)
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
