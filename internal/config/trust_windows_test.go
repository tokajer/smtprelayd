// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package config

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// wellKnown builds a SID without a name lookup, so these tests run on any
// Windows machine and in any locale -- including one where the service
// account does not exist, which is every machine before the MSI has run.
func wellKnown(t *testing.T, w windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(w)
	if err != nil {
		t.Fatalf("CreateWellKnownSid: %v", err)
	}
	return sid
}

// aclGranting builds a protected-style DACL granting full control to each of
// sids, the shape SecureDataDir writes.
func aclGranting(t *testing.T, sids ...*windows.SID) *windows.ACL {
	t.Helper()
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	for _, sid := range sids {
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
		t.Fatalf("ACLFromEntries: %v", err)
	}
	return acl
}

// The regression this exists for. Until 2026-09-18 CheckDataDirACL verified
// only that the DACL was explicit, protected and non-empty, while its own
// comment and docs/guides/SECURITY.md both said it verified who it granted
// to. A protected DACL carrying one ACE for Everyone satisfied every
// structural test -- and on Windows this ACL is the only access control over
// the spool, the history database and a dpapi: secret, because mode bits do
// not apply and internal/spool's noFollow and ensureMode are no-ops that name
// this DACL as their cover.
func TestACLWithAnUnexpectedTrusteeIsRefused(t *testing.T) {
	system := wellKnown(t, windows.WinLocalSystemSid)
	admins := wellKnown(t, windows.WinBuiltinAdministratorsSid)
	everyone := wellKnown(t, windows.WinWorldSid)

	acl := aclGranting(t, system, admins, everyone)

	err := aclGrantsOnly(`C:\probe`, acl, []*windows.SID{system, admins})
	if err == nil {
		t.Fatal("a DACL granting Everyone full control was accepted")
	}
	// The operator has to learn which account, or the refusal is a puzzle.
	if !strings.Contains(err.Error(), everyone.String()) {
		t.Errorf("the error does not name the offending SID: %v", err)
	}
	// And how to get out of it.
	if !strings.Contains(err.Error(), "secure-datadir") {
		t.Errorf("the error does not name the remedy: %v", err)
	}
}

// The shape SecureDataDir writes has to pass, or the check is a service that
// never starts.
func TestACLWithOnlyExpectedTrusteesIsAccepted(t *testing.T) {
	system := wellKnown(t, windows.WinLocalSystemSid)
	admins := wellKnown(t, windows.WinBuiltinAdministratorsSid)
	// Stands in for NT SERVICE\smtprelayd, which does not exist on a machine
	// where the MSI has not run.
	users := wellKnown(t, windows.WinBuiltinUsersSid)

	acl := aclGranting(t, system, admins, users)

	if err := aclGrantsOnly(`C:\probe`, acl, []*windows.SID{system, admins, users}); err != nil {
		t.Fatalf("the ACL SecureDataDir writes was refused: %v", err)
	}
}

// A deny ACE can only narrow access. Refusing one would turn a tightening an
// operator made deliberately into a service that will not start, and the
// narrowing that actually breaks things reports itself when the spool cannot
// be opened.
func TestDenyEntriesAreLeftAlone(t *testing.T) {
	system := wellKnown(t, windows.WinLocalSystemSid)
	admins := wellKnown(t, windows.WinBuiltinAdministratorsSid)
	guests := wellKnown(t, windows.WinBuiltinGuestsSid)

	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.DENY_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(guests),
			},
		},
		{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(system),
			},
		},
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("ACLFromEntries: %v", err)
	}

	if err := aclGrantsOnly(`C:\probe`, acl, []*windows.SID{system, admins}); err != nil {
		t.Errorf("a deny entry for an unexpected account was treated as a grant: %v", err)
	}
}

// CheckDataDirACL still refuses the structural faults it always did, on a
// path that is not a directory at all.
func TestCheckDataDirACLRejectsANonDirectory(t *testing.T) {
	file := t.TempDir() + `\not-a-dir.txt`
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckDataDirACL(file); err == nil {
		t.Fatal("a file was accepted as the data directory")
	}
}
