// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package ostrust

import (
	"errors"
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

// CheckSecretFile mirrors CheckConfigFile on Windows: the reparse-point
// refusal is the portable half, and the directory holding the file is
// checked for the same reason, so that a secret cannot be swapped by
// replacing it from a directory the caller does not control. Mode bits and
// ownership are not the access-control mechanism here; a secret outside the
// data directory is the operator's to protect with an ACL.
func CheckSecretFile(path string) error {
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

// aclGrantsOnly is the data directory's verdict, with the expected trustees
// passed in rather than resolved. Separated for the test: dataDirTrustees
// looks up NT SERVICE\smtprelayd, which does not exist until the service is
// installed, so a test that had to go through it could not run on a plain
// Windows machine -- and this is the one function here whose logic is worth
// asserting rather than its plumbing.
//
// Any access counts and inherit-only entries are not skipped: the directory
// is the parent of everything the service writes, so an entry that applies
// only to its children still applies to the spool.
func aclGrantsOnly(path string, acl *windows.ACL, expected []*windows.SID) error {
	g, err := foreignGrant(acl, expected, grantRule{})
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if g != nil {
		return fmt.Errorf("%s: DACL grants access to %s, which is not SYSTEM, "+
			"BUILTIN\\Administrators or %s%s",
			path, sidName(g.sid), dataDirServiceAccount, aclRemedy)
	}
	return nil
}

// grantRule says which allow ACEs foreignGrant reports. The zero value is
// the data directory's rule, and must stay so: any access counts, nothing is
// skipped, and only ACCESS_ALLOWED_ACE_TYPE is read, as it always was.
type grantRule struct {
	// mask restricts the report to ACEs granting any of these bits; 0
	// means any access at all.
	mask windows.ACCESS_MASK

	// skipInheritOnly leaves out entries that do not apply to the object
	// itself, which is right for a check about that object and wrong for
	// one about everything below it.
	skipInheritOnly bool

	// otherAllowTypes reports every allow-type ACE other than
	// ACCESS_ALLOWED_ACE_TYPE as foreign without reading its trustee: an
	// object or callback ACE stores GUIDs or condition data before its SID,
	// so SidStart does not mark one, and an allow entry this cannot read is
	// one it cannot vouch for. Such ACEs have no business on a file or a
	// service; one appearing there is worth a refusal, not a pass.
	otherAllowTypes bool
}

// grant is one ACE foreignGrant refused. sid is nil when the ACE is of a type
// whose trustee is not read; see grantRule.otherAllowTypes.
type grant struct {
	sid     *windows.SID
	mask    windows.ACCESS_MASK
	aceType byte
}

// who names the trustee for an error message.
func (g *grant) who() string {
	if g.sid == nil {
		return fmt.Sprintf("an allow entry of ACE type %d, whose trustee this check does not read", g.aceType)
	}
	return sidName(g.sid)
}

// nonGrantingACETypes are the ACE types that can only narrow access or only
// record it, by their winnt.h values: x/sys names only the first two. Every other type is an allow type
// or one this code does not know, and otherAllowTypes treats both alike.
var nonGrantingACETypes = map[byte]bool{
	windows.ACCESS_DENIED_ACE_TYPE: true,
	0x02:                           true, // SYSTEM_AUDIT_ACE_TYPE
	0x03:                           true, // SYSTEM_ALARM_ACE_TYPE
	0x06:                           true, // ACCESS_DENIED_OBJECT_ACE_TYPE
	0x07:                           true, // SYSTEM_AUDIT_OBJECT_ACE_TYPE
	0x08:                           true, // SYSTEM_ALARM_OBJECT_ACE_TYPE
	0x0a:                           true, // ACCESS_DENIED_CALLBACK_ACE_TYPE
	0x0c:                           true, // ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
	0x0d:                           true, // SYSTEM_AUDIT_CALLBACK_ACE_TYPE
	0x0e:                           true, // SYSTEM_ALARM_CALLBACK_ACE_TYPE
	0x0f:                           true, // SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
	0x10:                           true, // SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
	0x11:                           true, // SYSTEM_MANDATORY_LABEL_ACE_TYPE
	0x12:                           true, // SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
	0x13:                           true, // SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
	0x14:                           true, // SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE
	0x15:                           true, // SYSTEM_ACCESS_FILTER_ACE_TYPE
}

// foreignGrant is the one ACE walker in this package: it returns the first
// allow ACE that rule selects and that names a SID outside trusted, or nil
// when there is none.
//
// Deny ACEs are not looked at: they can only narrow what an allow grants,
// and every caller here asks who may do something, not who may not.
func foreignGrant(acl *windows.ACL, trusted []*windows.SID, rule grantRule) (*grant, error) {
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return nil, fmt.Errorf("could not read ACE %d: %w", i, err)
		}
		// The header and the mask sit at the same offsets in every ACE type,
		// so both may be read before the type is known; the SID may not.
		aceType := ace.Header.AceType
		if aceType != windows.ACCESS_ALLOWED_ACE_TYPE &&
			(!rule.otherAllowTypes || nonGrantingACETypes[aceType]) {
			continue
		}
		if rule.skipInheritOnly && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if rule.mask != 0 && ace.Mask&rule.mask == 0 {
			continue
		}
		if aceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return &grant{mask: ace.Mask, aceType: aceType}, nil
		}
		// The SID is stored inline after the fixed header, which is what
		// SidStart marks the beginning of rather than holds.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if slices.ContainsFunc(trusted, sid.Equals) {
			continue
		}
		return &grant{sid: sid, mask: ace.Mask, aceType: aceType}, nil
	}
	return nil, nil
}

// fileWriteMask is every right that lets the holder change what runs: write
// or append to the file or, on a directory, add a file or subdirectory to it
// -- the planted DLL or the renamed-aside binary -- delete it or a child,
// rewrite its DACL or take ownership, and the generic and MAXIMUM_ALLOWED
// forms that expand to those. Reading and executing are not in it: Users
// may run the relay's binary, and Program Files grants them exactly that.
const fileWriteMask windows.ACCESS_MASK = 0x2 | // FILE_WRITE_DATA, FILE_ADD_FILE
	0x4 | // FILE_APPEND_DATA, FILE_ADD_SUBDIRECTORY
	0x40 | // FILE_DELETE_CHILD
	windows.DELETE |
	windows.WRITE_DAC |
	windows.WRITE_OWNER |
	windows.GENERIC_ALL |
	windows.GENERIC_WRITE |
	windows.MAXIMUM_ALLOWED

// writerRule is the rule for every "who may modify this" check below.
// Inherit-only entries are skipped: Program Files carries CREATOR OWNER full
// control as one, and it applies to what an account creates below, never to
// the object itself -- whoever could create something there would already
// have been refused for the right that let them.
var writerRule = grantRule{mask: fileWriteMask, skipInheritOnly: true, otherAllowTypes: true}

// trustedInstallerSID is NT SERVICE\TrustedInstaller, which owns and may
// write %ProgramFiles% itself. It has no WELL_KNOWN_SID_TYPE, and looking it
// up by name would make a German install depend on a localised name; a
// service SID is the SHA-1 of the service name, so this string is the same
// on every Windows machine.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// binaryTrustees are the accounts that may own and write the executable and
// its directory: what owns and writes %ProgramFiles% on a stock install.
//
// The service account is deliberately not among them. A service that can
// rewrite its own binary turns any code execution inside it into a
// persistent one that survives the restart meant to clear it, and a virtual
// account never needs to write there.
func binaryTrustees() ([]*windows.SID, error) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, fmt.Errorf("NT AUTHORITY\\SYSTEM: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("BUILTIN\\Administrators: %w", err)
	}
	installer, err := windows.StringToSid(trustedInstallerSID)
	if err != nil {
		return nil, fmt.Errorf("NT SERVICE\\TrustedInstaller: %w", err)
	}
	return []*windows.SID{system, admins, installer}, nil
}

// binaryRemedy is the way out of a refusal below: the MSI's own location,
// which already has the right owner and DACL, or the icacls line for an
// operator who put the binary elsewhere on purpose. icacls is given SIDs, as
// "*S-1-...", because the account names are localised.
const binaryRemedy = `; install it under %ProgramFiles% as the MSI does`

func binaryOwnerRemedy(path string) string {
	return binaryRemedy + `, or from an elevated prompt run: icacls "` + path + `" /setowner *S-1-5-32-544`
}

func binaryGrantRemedy(path string, g *grant) string {
	if g.sid == nil {
		return binaryRemedy
	}
	return binaryRemedy + `, or from an elevated prompt run: icacls "` + path + `" /remove:g *` + g.sid.String() +
		` (an inherited entry has to be removed on the parent directory instead)`
}

// CheckExecutable refuses to start from a binary that an account other than
// SYSTEM, BUILTIN\Administrators or TrustedInstaller could replace: a
// writable executable, or a directory a DLL or a substitute binary can be
// placed into, is code execution as the service account at the next restart
// (docs/dev/EXPLOIT-SURFACE.md section 1). Both are checked for owner and
// DACL, because an owner can rewrite the DACL whatever it currently says.
func CheckExecutable(exe string) error {
	dir := filepath.Dir(exe)
	if err := CheckDir(dir); err != nil {
		return err
	}
	fi, err := os.Lstat(exe)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink or reparse point; refusing to run from it", exe)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", exe)
	}

	trusted, err := binaryTrustees()
	if err != nil {
		return fmt.Errorf("cannot resolve the expected owners: %w", err)
	}
	for _, p := range []string{dir, exe} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return fmt.Errorf("%s: could not read owner and ACL: %w", p, err)
		}
		if err := checkBinaryDescriptor(p, sd, trusted); err != nil {
			return err
		}
	}
	return nil
}

// checkBinaryDescriptor is CheckExecutable's verdict on one descriptor, apart
// from the file system so the test can feed it descriptors built from SDDL.
// It is also the TLS key directory's verdict, with that check's trustees.
func checkBinaryDescriptor(path string, sd *windows.SECURITY_DESCRIPTOR, trusted []*windows.SID) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s: owner cannot be read%s", path, binaryRemedy)
	}
	if !slices.ContainsFunc(trusted, owner.Equals) {
		return fmt.Errorf("%s is owned by %s, not SYSTEM, BUILTIN\\Administrators or TrustedInstaller%s",
			path, sidName(owner), binaryOwnerRemedy(path))
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: no DACL present%s", path, binaryRemedy)
	}
	if acl == nil {
		return fmt.Errorf("%s: DACL is empty (everyone has full control)%s", path, binaryRemedy)
	}
	g, err := foreignGrant(acl, trusted, writerRule)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if g != nil {
		return fmt.Errorf("%s: DACL lets %s modify it (access mask 0x%x)%s",
			path, g.who(), g.mask, binaryGrantRemedy(path, g))
	}
	return nil
}

// keyRemedy is the way out of a refusal of the TLS key's DACL. Inside the
// data directory the key inherits the DACL secure-datadir writes, which is
// already exactly the three accounts allowed here.
const keyRemedy = `; keep key_file inside the data directory, whose DACL "smtprelayd secure-datadir" writes`

func keyOwnerRemedy(path string) string {
	return keyRemedy + `, or from an elevated prompt run: icacls "` + path + `" /setowner *S-1-5-32-544`
}

func keyGrantRemedy(path string, g *grant) string {
	if g.sid == nil {
		return keyRemedy
	}
	return keyRemedy + `, or from an elevated prompt run: icacls "` + path + `" /inheritance:r /remove:g *` + g.sid.String() +
		` and grant the service account read access if it then has none`
}

// CheckKeyFile refuses a TLS private key that an account other than SYSTEM,
// BUILTIN\Administrators or the service account can open at all, own, or
// replace: one that reads it can impersonate the relay to every device that
// trusts it, and one that writes it chooses the key the relay presents
// (docs/dev/EXPLOIT-SURFACE.md section 1).
//
// The DACL alone is not enough. Whoever owns the key can rewrite its DACL,
// and whoever can write its directory can put a different key there with a
// DACL that is clean, so the owner and the directory are checked as well.
// The directory's rule is the binary's -- who may modify it, not who may read
// it -- with the service account added, since keys live in the data
// directory and that grants the service full control.
func CheckKeyFile(path string) error {
	dir := filepath.Dir(path)
	if err := CheckDir(dir); err != nil {
		return fmt.Errorf("directory of TLS key %s: %w", path, err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("TLS key %s is a symlink or reparse point; point key_file at the file itself", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("TLS key %s is not a regular file", path)
	}
	system, admins, service, err := dataDirTrustees()
	if err != nil {
		return fmt.Errorf("TLS key %s: cannot resolve the expected trustees: %w", path, err)
	}
	installer, err := windows.StringToSid(trustedInstallerSID)
	if err != nil {
		return fmt.Errorf("NT SERVICE\\TrustedInstaller: %w", err)
	}

	const info = windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION
	dirSD, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, info)
	if err != nil {
		return fmt.Errorf("directory of TLS key %s: could not read owner and ACL: %w", path, err)
	}
	if err := checkKeyDirDescriptor(path, dir, dirSD, []*windows.SID{system, admins, installer, service}); err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info)
	if err != nil {
		return fmt.Errorf("TLS key %s: could not read owner and ACL: %w", path, err)
	}
	return checkKeyDescriptor(path, sd, []*windows.SID{system, admins, service}, installer)
}

// checkKeyDirDescriptor applies checkBinaryDescriptor's rule to the key's
// directory, prefixed so the operator can tell it from the binary's check.
func checkKeyDirDescriptor(path, dir string, sd *windows.SECURITY_DESCRIPTOR, trusted []*windows.SID) error {
	if err := checkBinaryDescriptor(dir, sd, trusted); err != nil {
		return fmt.Errorf("directory of TLS key %s: %w", path, err)
	}
	return nil
}

// checkKeyDescriptor is CheckKeyFile's verdict on the key's own descriptor,
// separated for the same reason aclGrantsOnly is: the service account does
// not exist on a test machine. trusted may own the key and be granted access
// to it; installer may own it too -- a key in a TrustedInstaller-owned tree
// is not one an unprivileged account placed -- but is granted nothing.
func checkKeyDescriptor(path string, sd *windows.SECURITY_DESCRIPTOR, trusted []*windows.SID, installer *windows.SID) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("TLS key %s: owner cannot be read%s", path, keyRemedy)
	}
	if !slices.ContainsFunc(trusted, owner.Equals) && !owner.Equals(installer) {
		return fmt.Errorf("TLS key %s is owned by %s, not SYSTEM, BUILTIN\\Administrators, %s or TrustedInstaller%s",
			path, sidName(owner), dataDirServiceAccount, keyOwnerRemedy(path))
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("TLS key %s: no DACL present%s", path, keyRemedy)
	}
	if acl == nil {
		return fmt.Errorf("TLS key %s: DACL is empty (everyone has full control)%s", path, keyRemedy)
	}
	g, err := foreignGrant(acl, trusted, grantRule{skipInheritOnly: true, otherAllowTypes: true})
	if err != nil {
		return fmt.Errorf("TLS key %s: %w", path, err)
	}
	if g != nil {
		return fmt.Errorf("TLS key %s: DACL grants access to %s, which is not SYSTEM, "+
			"BUILTIN\\Administrators or %s%s", path, g.who(), dataDirServiceAccount, keyGrantRemedy(path, g))
	}
	return nil
}

// serviceControlMask is every service right that changes what the service
// is rather than asking about it or starting it: SERVICE_CHANGE_CONFIG
// rewrites the binary path, which is code execution as the service account
// -- LocalSystem, if the account is changed with it -- and the rest rewrite
// the DACL, take ownership or delete. SERVICE_ALL_ACCESS and the generic
// forms include SERVICE_CHANGE_CONFIG and so are refused through it.
const serviceControlMask windows.ACCESS_MASK = windows.SERVICE_CHANGE_CONFIG |
	windows.DELETE |
	windows.WRITE_DAC |
	windows.WRITE_OWNER |
	windows.GENERIC_ALL |
	windows.GENERIC_WRITE

// CheckServiceDACL verifies a service's security descriptor: only SYSTEM and
// BUILTIN\Administrators may change its configuration, its DACL, its owner,
// or delete it (docs/dev/EXPLOIT-SURFACE.md section 2). It lives here rather
// than in cmd/smtprelayd because reading an ACE's SID needs unsafe, and this
// file is the one allowed it.
func CheckServiceDACL(sd *windows.SECURITY_DESCRIPTOR) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("NT AUTHORITY\\SYSTEM: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("BUILTIN\\Administrators: %w", err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("service has no DACL: %w", err)
	}
	if acl == nil {
		return errors.New("service DACL is empty (everyone has full control)")
	}
	// A service has no children, so there is no inherit-only entry to skip.
	g, err := foreignGrant(acl, []*windows.SID{system, admins},
		grantRule{mask: serviceControlMask, otherAllowTypes: true})
	if err != nil {
		return fmt.Errorf("service DACL: %w", err)
	}
	if g != nil {
		return fmt.Errorf("service DACL lets %s reconfigure or delete it (access mask 0x%x), "+
			"which only SYSTEM and BUILTIN\\Administrators may", g.who(), g.mask)
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
