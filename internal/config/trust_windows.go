// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

// checkSecretFile mirrors CheckConfigFile on Windows: the reparse-point
// refusal is the portable half, and the directory holding the file is
// checked for the same reason, so that a secret cannot be swapped by
// replacing it from a directory the caller does not control. Mode bits and
// ownership are not the access-control mechanism here; a secret outside the
// data directory is the operator's to protect with an ACL.
func checkSecretFile(path string) error {
	if err := CheckDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("directory of secret file %s: %w", path, err)
	}

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

// CheckDataDirACL verifies the data directory's ACL against what SecureDataDir
// wrote at installation, in two halves: the descriptor's shape here -- an
// explicit, protected, non-empty DACL on a real directory that is not a
// reparse point -- and then, in checkDataDirACEs, who it actually grants to.
//
// Both halves are needed. Until 2026-09-18 only the first existed while this
// comment already claimed the second, so a protected DACL carrying one ACE for
// Everyone passed. The identities are the half that matters, since an ACE for
// an unexpected account is the whole exposure; a narrower mask on an expected
// one only costs the service access to its own files, which it reports itself.
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

	return checkDataDirACEs(path, acl)
}

// checkDataDirACEs is the half that reads the ACL rather than its shape.
//
// Without it CheckDataDirACL accepted any protected, non-empty DACL: one ACE
// granting Everyone full control passed every structural test above. That
// matters more here than the same gap would elsewhere, because on Windows
// this ACL is not one control among several -- it is the only one. Mode bits
// do not apply, so internal/spool's noFollow and ensureMode are no-ops that
// name this DACL as what covers them, and MS365-AUTH.md tells an operator to
// keep a dpapi: secret inside the data directory for the same reason:
// CRYPTPROTECT_LOCAL_MACHINE stops a copy being useful on another host, not
// another process on this one.
//
// An allow ACE naming anything outside dataDirTrustees is refused. Deny ACEs
// are left alone: they can only narrow access, and one that narrows it too
// far surfaces as the service failing to open its own spool, which is a
// clearer message than anything this could produce.
func checkDataDirACEs(path string, acl *windows.ACL) error {
	system, admins, service, err := dataDirTrustees()
	if err != nil {
		return fmt.Errorf("%s: cannot resolve the expected trustees: %w", path, err)
	}
	return aclGrantsOnly(path, acl, []*windows.SID{system, admins, service})
}

// aclGrantsOnly is the loop itself, with the expected trustees passed in
// rather than resolved. Separated for the test: dataDirTrustees looks up
// NT SERVICE\smtprelayd, which does not exist until the service is
// installed, so a test that had to go through it could not run on a plain
// Windows machine -- and this is the one function here whose logic is worth
// asserting rather than its plumbing.
func aclGrantsOnly(path string, acl *windows.ACL, expected []*windows.SID) error {
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return fmt.Errorf("%s: could not read ACE %d: %w", path, i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		// The SID is stored inline after the fixed header, which is what
		// SidStart marks the beginning of rather than holds.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if slices.ContainsFunc(expected, sid.Equals) {
			continue
		}
		return fmt.Errorf("%s: DACL grants access to %s, which is not SYSTEM, "+
			"BUILTIN\\Administrators or %s%s",
			path, sidName(sid), dataDirServiceAccount, aclRemedy)
	}
	return nil
}

// sidName renders a SID for the error above, preferring the account name an
// operator would recognise and falling back to the string form when it does
// not resolve -- a SID from a deleted account or an unreachable domain still
// has to be nameable in the message that refuses it.
func sidName(sid *windows.SID) string {
	if account, domain, _, err := sid.LookupAccount(""); err == nil {
		if domain != "" {
			return domain + `\` + account + " (" + sid.String() + ")"
		}
		return account + " (" + sid.String() + ")"
	}
	return sid.String()
}
