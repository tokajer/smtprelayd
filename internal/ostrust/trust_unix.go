// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package ostrust

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

// CheckSecretFile applies the config file's trust requirement to a file
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
func CheckSecretFile(path string) error {
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

// CheckExecutable applies checkTrusted to the running binary and the
// directory holding it: a writable binary, or a directory it can be replaced
// in, is code execution as the service account at the next restart
// (docs/dev/EXPLOIT-SURFACE.md section 1). The directory alone used to be
// checked, which left a binary chmod'ed 0666 inside a sound directory.
func CheckExecutable(exe string) error {
	if err := checkTrusted(filepath.Dir(exe), true); err != nil {
		return err
	}
	return checkTrusted(exe, false)
}

// CheckKeyFile applies the trust check to the listener's TLS private key and
// the directory holding it (docs/dev/EXPLOIT-SURFACE.md section 1). It is
// CheckSecretFile with one difference: the group may read. gen-cert, run as
// root, gives the key the configuration file's group and mode 0640 so the
// service account can read it, and that layout -- root:smtprelayd 0640 in a
// 0750 directory -- is the one the package documents. Nobody else may do
// anything with it, and nobody but the owner may write it: whoever reads the
// key can impersonate the relay to every device that trusts it, and whoever
// writes it chooses the key the relay presents.
func CheckKeyFile(path string) error {
	if err := checkTrusted(filepath.Dir(path), true); err != nil {
		return fmt.Errorf("directory of TLS key %s: %w", path, err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("TLS key %s is a symlink; point key_file at the file itself", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("TLS key %s is not a regular file", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot determine ownership", path)
	}
	uid := os.Getuid()
	if int(st.Uid) != 0 && int(st.Uid) != uid {
		return fmt.Errorf("TLS key %s is owned by uid %d, expected root or uid %d; "+
			"fix it with: chown root:<service group> %s", path, st.Uid, uid, path)
	}
	if perm := fi.Mode().Perm(); perm&0o027 != 0 {
		return fmt.Errorf("TLS key %s has mode %04o, which lets the group write it or other accounts use it; "+
			"fix it with: chmod 0640 %s", path, perm, path)
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
