// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package config

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// dataDirServiceAccount must stay identical to the UserName in
// windowsServiceConfig() (cmd/smtprelayd/service_windows.go). The DACL and the
// SCM registration are the same contract seen from two sides.
const dataDirServiceAccount = `NT SERVICE\smtprelayd`

// fileAllAccess is what icacls prints as "F". GENERIC_ALL is deliberately not
// used: generic bits are mapped to specific ones for the object the ACE is set
// on, but are carried unmapped into ACEs inherited by files created later, so
// the effective mask would differ between the directory and its contents.
const fileAllAccess windows.ACCESS_MASK = 0x1F01FF

// SecureDataDir writes the data directory DACL that CheckDataDirACL verifies:
// full control for SYSTEM, BUILTIN\Administrators and the service account,
// inheritable to files and subdirectories, and protected against inheritance
// from %ProgramData% — whose BUILTIN\Users:(OI)(CI)(RX) would otherwise let
// every interactive account read the spool, and with it message bodies.
//
// Existing contents need no separate pass: setting an inheritable DACL on the
// directory makes Windows recompute the inherited ACEs of everything below it.
func SecureDataDir(path string) error {
	if err := CheckDir(path); err != nil {
		return err
	}

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("BUILTIN\\Administrators: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("NT AUTHORITY\\SYSTEM: %w", err)
	}
	// Well-known SIDs are constructed, not looked up by name, because the
	// names are localised: "Administrators" does not resolve on a German or
	// French install.
	service, _, _, err := windows.LookupSID("", dataDirServiceAccount)
	if err != nil {
		return fmt.Errorf("%s: %w", dataDirServiceAccount, err)
	}

	entries := make([]windows.EXPLICIT_ACCESS, 0, 3)
	for _, sid := range []*windows.SID{system, admins, service} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}

	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("%s: could not build ACL: %w", path, err)
	}

	// The owner is reset along with the DACL. A directory owned by anything
	// else cannot be re-ACLed even by an administrator without takeown, and
	// takeown rewrites the DACL on its way through, dropping the service
	// account's ACE — which then looks like an unrelated second fault.
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins, nil, acl, nil)
	if err != nil {
		return fmt.Errorf("%s: could not set ACL: %w", path, err)
	}
	return nil
}
