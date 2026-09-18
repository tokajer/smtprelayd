// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SecureDataDir writes a protected, inheritable DACL and resets the owner, so
// Windows recomputes the inherited ACEs of everything below the path it is
// given. Pointed at C:\ProgramData -- one missing path element, and a
// plausible typo -- that takes every non-administrator's access to every
// installed application's data. Pointed at a volume root it takes the
// machine.
//
// purgeDataDir has guarded its own resolution since it was written; this one
// had nothing, although every ACL error the binary prints ends by telling the
// operator to run secure-datadir from an elevated prompt -- so it is reached
// exactly when something about the configured path has just gone wrong.
func TestRefuseSystemDirRejectsWhatBreaksTheMachine(t *testing.T) {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		t.Skip("ProgramData is unset")
	}

	for _, dir := range []string{
		`C:\`,
		filepath.VolumeName(programData) + `\`,
		programData,
		programData + `\`, // a trailing separator must not evade the comparison
		os.Getenv("SystemRoot"),
	} {
		if dir == "" || dir == `\` {
			continue
		}
		t.Run(dir, func(t *testing.T) {
			err := refuseSystemDir(dir, "re-ACL")
			if err == nil {
				t.Fatalf("%q was accepted as a data directory", dir)
			}
			// The operator has to be able to act on the refusal.
			if !strings.Contains(err.Error(), "refusing to re-ACL") {
				t.Errorf("error does not name the refused action: %v", err)
			}
		})
	}
}

// A relocated data directory has to keep working: unlike purgeDataDir, this
// guard cannot insist on a particular name, only refuse the targets where
// being wrong is unrecoverable.
func TestRefuseSystemDirAcceptsARelocatedDataDir(t *testing.T) {
	for _, dir := range []string{
		filepath.Join(os.Getenv("ProgramData"), "SMTPRelayd"),
		`D:\MailSpool`,
		`C:\srv\smtprelayd-data`,
	} {
		if dir == "" {
			continue
		}
		if err := refuseSystemDir(dir, "re-ACL"); err != nil {
			t.Errorf("%q was refused but is a legitimate relocation: %v", dir, err)
		}
	}
}

// A relative path never reaches SecureDataDir. config.Validate rejects one
// first, but secure-datadir also runs before any configuration exists, on the
// config file's own directory, so this is not redundant.
func TestRefuseSystemDirRejectsARelativePath(t *testing.T) {
	if err := refuseSystemDir(`spool`, "re-ACL"); err == nil {
		t.Fatal("a relative path was accepted")
	}
}

// The guard is only worth having if it is still wired into the command. This
// covers the install-time path specifically: before the MSI has written a
// configuration, resolveDataDir falls back to the config file's own directory,
// so a config path directly under %ProgramData% resolves to %ProgramData%
// itself -- which is the shape of the accident, not a contrived input.
func TestDataDirTargetRefusesASystemDirectory(t *testing.T) {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		t.Skip("ProgramData is unset")
	}

	_, err := dataDirTarget(filepath.Join(programData, "smtprelayd.toml"))
	if err == nil {
		t.Fatal("secure-datadir would have re-ACLed %ProgramData%")
	}
	if !strings.Contains(err.Error(), "refusing to re-ACL") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// And the ordinary case still resolves, or the command is dead.
func TestDataDirTargetAcceptsTheInstalledLocation(t *testing.T) {
	dir := t.TempDir()

	got, err := dataDirTarget(filepath.Join(dir, "smtprelayd.toml"))
	if err != nil {
		t.Fatalf("the packaged layout was refused: %v", err)
	}
	if got != dir {
		t.Errorf("resolved to %q, want %q", got, dir)
	}
}
