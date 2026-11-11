// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package ostrust

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

// descriptor parses SDDL the way the tests below state a DACL: in the form
// icacls and sc.exe sdshow print, so a case reads as the machine state it
// stands for.
func descriptor(t *testing.T, sddl string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString(%q): %v", sddl, err)
	}
	return sd
}

// The data directory's check covers what lives below it, so an inherit-only
// entry is refused there even though the binary check below skips one.
func TestDataDirACLStillRefusesAnInheritOnlyGrant(t *testing.T) {
	system := wellKnown(t, windows.WinLocalSystemSid)
	admins := wellKnown(t, windows.WinBuiltinAdministratorsSid)
	sd := descriptor(t, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FR;;;WD)")
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := aclGrantsOnly(`C:\probe`, acl, []*windows.SID{system, admins}); err == nil {
		t.Fatal("an inherit-only grant to Everyone was accepted on the data directory")
	}
}

// programFiles is the shape of %ProgramFiles% and of what the MSI creates
// below it: owned by TrustedInstaller, full control for SYSTEM and
// Administrators, read and execute for Users, and CREATOR OWNER full control
// as an inherit-only entry that never applies to the directory itself.
const programFiles = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" +
	"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GA;;;CO)"

// A writable binary or a binary directory anyone can add a DLL to is code
// execution as the service account at the next restart. Until 2026-11-11
// only the directory's type was checked on Windows, not who could write it.
func TestCheckBinaryDescriptor(t *testing.T) {
	trusted, err := binaryTrustees()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, sddl string
		ok         bool
	}{
		{"Program Files", programFiles, true},
		{"installed by the MSI as SYSTEM", "O:SY" + programFiles[len("O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"):], true},
		{"owned by Administrators", "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)", true},
		{"a deny entry is left alone", programFiles + "(D;;FA;;;AU)", true},
		{"an inherit-only grant does not apply to the object", programFiles + "(A;OICIIO;FA;;;AU)", true},
		{"Users may add a file", programFiles + "(A;;0x2;;;BU)", false},
		{"Users may add a subdirectory", programFiles + "(A;;0x4;;;BU)", false},
		{"Users may delete a child", programFiles + "(A;;0x40;;;BU)", false},
		{"Authenticated Users have full control", programFiles + "(A;;FA;;;AU)", false},
		{"Everyone may rewrite the DACL", programFiles + "(A;;WD;;;WD)", false},
		{"Users may take ownership", programFiles + "(A;;WO;;;BU)", false},
		{"Users hold GENERIC_WRITE", programFiles + "(A;;GW;;;BU)", false},
		{"Users hold MAXIMUM_ALLOWED", programFiles + "(A;;0x2000000;;;BU)", false},
		{"owned by Users", "O:BUD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)", false},
		{"null DACL", "O:BAD:NO_ACCESS_CONTROL", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkBinaryDescriptor(`C:\probe`, descriptor(t, tc.sddl), trusted)
			switch {
			case tc.ok && err != nil:
				t.Fatalf("refused: %v", err)
			case !tc.ok && err == nil:
				t.Fatal("accepted")
			case !tc.ok && !strings.Contains(err.Error(), "%ProgramFiles%"):
				t.Errorf("the error does not name the remedy: %v", err)
			}
		})
	}
}

// The service account is deliberately outside the trusted set: a service
// that can rewrite its own binary turns one compromise into a permanent one.
// Users stands in for NT SERVICE\smtprelayd, which needs the MSI to exist.
func TestCheckBinaryDescriptorRefusesAWritableServiceAccount(t *testing.T) {
	trusted, err := binaryTrustees()
	if err != nil {
		t.Fatal(err)
	}
	sd := descriptor(t, programFiles+"(A;;0x1301bf;;;BU)") // icacls "M"
	if err := checkBinaryDescriptor(`C:\probe`, sd, trusted); err == nil {
		t.Fatal("modify access for an account outside the trusted set was accepted")
	}
}

// The TLS key may be opened by nobody but SYSTEM, Administrators and the
// service account, the data directory's three. Users again stands in for the
// service account.
func TestCheckKeyDescriptor(t *testing.T) {
	trusted := []*windows.SID{
		wellKnown(t, windows.WinLocalSystemSid),
		wellKnown(t, windows.WinBuiltinAdministratorsSid),
		wellKnown(t, windows.WinBuiltinUsersSid),
	}
	installer, err := windows.StringToSid(trustedInstallerSID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, sddl string
		ok         bool
	}{
		{"inherited from the data directory", "O:BAD:P(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;BU)", true},
		{"read-only for the service", "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)", true},
		{"owned by SYSTEM", "O:SYD:P(A;;FA;;;SY)(A;;FR;;;BU)", true},
		{"owned by the service account", "O:BUD:P(A;;FA;;;SY)(A;;FR;;;BU)", true},
		{"owned by TrustedInstaller", "O:" + trustedInstallerSID + "D:P(A;;FA;;;SY)(A;;FR;;;BU)", true},
		{"a deny entry is left alone", "O:BAD:P(A;;FA;;;SY)(D;;FA;;;AU)", true},
		// The owner can rewrite whatever DACL the key carries.
		{"owned by Authenticated Users", "O:AUD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)", false},
		{"Authenticated Users may read it", "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)(A;;FR;;;AU)", false},
		{"Everyone may read its attributes", "O:BAD:P(A;;FA;;;SY)(A;;0x80;;;WD)", false},
		{"an object allow entry", "O:BAD:P(A;;FA;;;SY)(OA;;FR;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)", false},
		{"null DACL", "O:BAD:NO_ACCESS_CONTROL", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkKeyDescriptor(`C:\probe\relay.key`, descriptor(t, tc.sddl), trusted, installer)
			switch {
			case tc.ok && err != nil:
				t.Fatalf("refused: %v", err)
			case !tc.ok && err == nil:
				t.Fatal("accepted")
			case !tc.ok && !strings.Contains(err.Error(), "secure-datadir"):
				t.Errorf("the error does not name the remedy: %v", err)
			}
		})
	}
}

// A key with a clean DACL proves nothing if another account can write its
// directory: it can delete the key and put its own there, with whatever
// DACL it likes. The directory is held to the binary's rule, with the
// service account (Users stands in) added because the data directory grants
// it full control and keys live there.
func TestCheckKeyDirDescriptor(t *testing.T) {
	installer, err := windows.StringToSid(trustedInstallerSID)
	if err != nil {
		t.Fatal(err)
	}
	trusted := []*windows.SID{
		wellKnown(t, windows.WinLocalSystemSid),
		wellKnown(t, windows.WinBuiltinAdministratorsSid),
		installer,
		wellKnown(t, windows.WinBuiltinUsersSid),
	}
	const dataDir = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)"
	for _, tc := range []struct {
		name, sddl string
		ok         bool
	}{
		{"the data directory secure-datadir writes", dataDir, true},
		{"Everyone may list it", dataDir + "(A;;0x1200a9;;;WD)", true},
		{"Authenticated Users may add a file", dataDir + "(A;;0x2;;;AU)", false},
		{"Authenticated Users may delete a child", dataDir + "(A;;0x40;;;AU)", false},
		{"owned by Authenticated Users", "O:AUD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", false},
		{"null DACL", "O:BAD:NO_ACCESS_CONTROL", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkKeyDirDescriptor(`C:\probe\tls\relay.key`, `C:\probe\tls`, descriptor(t, tc.sddl), trusted)
			switch {
			case tc.ok && err != nil:
				t.Fatalf("refused: %v", err)
			case !tc.ok && err == nil:
				t.Fatal("accepted")
			case !tc.ok && !strings.Contains(err.Error(), "directory of TLS key"):
				t.Errorf("the error does not say it is about the key's directory: %v", err)
			}
		})
	}
}

// An object or callback ACE keeps its SID behind GUIDs or condition data, so
// the walker cannot read whom it grants to; for the binary, the key and the
// service such an entry is refused rather than passed unread. The data
// directory's walk is unchanged and still reads only ACCESS_ALLOWED_ACE_TYPE.
func TestOtherAllowTypesAreRefusedOnlyByTheNewChecks(t *testing.T) {
	const objectGrant = "(OA;;0x2;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)"
	trusted, err := binaryTrustees()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkBinaryDescriptor(`C:\probe`, descriptor(t, programFiles+objectGrant), trusted); err == nil {
		t.Error("an object allow entry granting write was accepted on the binary")
	}
	// An object deny entry only narrows, here as for plain deny entries.
	if err := checkBinaryDescriptor(`C:\probe`, descriptor(t,
		programFiles+"(OD;;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)"), trusted); err != nil {
		t.Errorf("an object deny entry was refused: %v", err)
	}

	system := wellKnown(t, windows.WinLocalSystemSid)
	admins := wellKnown(t, windows.WinBuiltinAdministratorsSid)
	acl, _, err := descriptor(t, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"+objectGrant).DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := aclGrantsOnly(`C:\probe`, acl, []*windows.SID{system, admins}); err != nil {
		t.Errorf("the data directory check changed behaviour for an object entry: %v", err)
	}
}
