// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tokajer/smtprelayd/internal/config"
)

// verifyDataDirSecurity checks that the data directory has the ACL set by the
// installer on Windows.
func verifyDataDirSecurity(dataDir string) error {
	return config.CheckDataDirACL(dataDir)
}

// resolveDataDir is where both data-directory commands get their target: the
// configured data_dir when the configuration still loads, the config file's
// own directory otherwise (at install time no configuration exists yet and
// the location the MSI creates is used).
func resolveDataDir(configPath string) string {
	if cfg, err := config.Load(configPath); err == nil {
		return cfg.Service.DataDir
	}
	return filepath.Dir(configPath)
}

// systemDirs are the directories whose ACL must never be rewritten, read from
// the environment rather than by name because those names are localised.
//
// It is a list of what breaks the machine, not a proof that anything else is
// smtprelayd's to touch -- there is no such proof available. A relocated
// data_dir has to keep working, so refuseSystemDir cannot demand a particular
// name the way purgeDataDir does; what it can do is refuse the handful of
// targets where being wrong is unrecoverable.
func systemDirs() []string {
	var out []string
	for _, v := range []string{
		"SystemRoot", "ProgramData", "ProgramFiles", "ProgramFiles(x86)",
		"PUBLIC", "USERPROFILE", "SystemDrive",
	} {
		if p := os.Getenv(v); p != "" {
			out = append(out, filepath.Clean(p))
		}
	}
	return out
}

// refuseSystemDir rejects a resolved directory that is too broad to act on.
//
// SecureDataDir writes a protected DACL with SUB_CONTAINERS_AND_OBJECTS_INHERIT
// and resets the owner, and its own comment states the consequence: Windows
// recomputes the inherited ACEs of everything below. Pointed at C:\ProgramData
// -- one missing path element, and a plausible one -- that takes access to
// every installed application's data away from every non-administrator on the
// machine. Pointed at a volume root it takes the machine.
//
// This is not defence against an attacker: the command needs elevation, and
// anyone with it could run icacls directly. It is defence against a typo,
// which is the way it actually happens -- every ACL error this binary prints
// ends by telling the operator to run "secure-datadir" from an elevated
// prompt, so the command is reached precisely when something about the
// configured path has just gone wrong.
//
// purgeDataDir keeps its own, stricter rule instead of sharing this one: it
// deletes recursively, so it can afford to insist on the exact name and
// refuse a relocated directory outright. Securing one has to keep working
// wherever the operator put it.
func refuseSystemDir(dir, action string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("refusing to %s %q: not an absolute path", action, dir)
	}
	clean := filepath.Clean(dir)
	if filepath.Dir(clean) == clean {
		return fmt.Errorf("refusing to %s %q: that is a volume root", action, clean)
	}
	for _, sys := range systemDirs() {
		if strings.EqualFold(clean, sys) {
			return fmt.Errorf("refusing to %s %q: that is a system directory, not the smtprelayd data directory"+
				" -- check service.data_dir in the configuration", action, clean)
		}
	}
	return nil
}

// dataDirTarget resolves the directory secure-datadir will act on and applies
// the refusal to it. It exists apart from secureDataDir so that the guard is
// reachable from a test: secureDataDir itself goes on to write a real DACL to
// a real directory, so nothing can call it to find out whether the refusal is
// still wired up.
func dataDirTarget(configPath string) (string, error) {
	dir := resolveDataDir(configPath)
	if err := refuseSystemDir(dir, "re-ACL"); err != nil {
		return "", err
	}
	return dir, nil
}

// secureDataDir writes that ACL. It runs from the MSI as a deferred custom
// action and from an elevated prompt when an operator has to recover a
// directory whose ACL was lost — never from the running service, which would
// mean a service that widens its own permissions at startup and would defeat
// verifyDataDirSecurity entirely.
//
// The directory is taken from the configuration when one is readable, so a
// relocated data_dir is secured too; at install time no configuration exists
// yet and the location the MSI creates is used.
func secureDataDir(configPath string) error {
	dir, err := dataDirTarget(configPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := config.SecureDataDir(dir); err != nil {
		return err
	}
	fmt.Printf("smtprelayd: data directory ACL set on %s\n", dir)
	return nil
}

// purgeDataDir removes the data directory entirely: the spool and the
// history database. It runs from the MSI as a deferred custom action,
// scheduled only when the operator answered "yes" to the uninstall dialog
// asking whether to also delete %ProgramData%\SMTPRelayd — the MSI does not
// remove it by default, since the spool may still hold accepted, undelivered
// mail; this is the explicit, opt-in path for an operator who wants it gone.
//
// dir is resolved exactly like secureDataDir's: the configured data_dir when
// the configuration still loads, the config file's own directory otherwise.
// Unlike secureDataDir, a resolved directory whose last path element is not
// "SMTPRelayd" is refused rather than acted on: this deletes recursively and
// runs unattended from a deferred custom action with no further
// confirmation, so a wrong resolution here must fail closed rather than
// remove whatever it computed.
//
// It also runs the same config.CheckDir symlink/reparse-point refusal
// secureDataDir already runs through SecureDataDir, for the same reason
// docs/dev/EXPLOIT-SURFACE.md §1 gives for checking it at startup: this is the
// one function in the tree that recurses into the data directory instead of
// only reading or ACLing it, so a junction planted at this path — before a
// fresh install or after an operator manually recreated it without the
// ACL — matters most exactly here, run as SYSTEM with no further
// confirmation. A missing directory is not an error: purge-datadir may run
// against a data directory that never existed or was already removed.
func purgeDataDir(configPath string) error {
	dir := resolveDataDir(configPath)
	if !filepath.IsAbs(dir) || !strings.EqualFold(filepath.Base(dir), "SMTPRelayd") {
		return fmt.Errorf("refusing to remove %q: does not look like the smtprelayd data directory", dir)
	}
	if err := config.CheckDir(dir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("refusing to remove %q: %w", dir, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	fmt.Printf("smtprelayd: data directory removed: %s\n", dir)
	return nil
}

// protectSecret reads a plaintext secret as a single line from stdin and
// writes it, encrypted with this machine's DPAPI key, to outPath — the file
// a dpapi:<path> reference in the configuration then points at. Run once,
// elevated, by whoever provisions the secret; the running service only ever
// decrypts, never encrypts.
//
// Reading the secret itself from stdin rather than a flag keeps it out of
// the process list and the shell's command history; -out is not secret and
// works like every other flag this command accepts — it must precede the
// command, since (flag).Parse stops at the first non-flag argument. The
// intended invocation pipes a masked prompt into it, e.g. from PowerShell:
//
//	$s = Read-Host -AsSecureString "Secret"
//	[Runtime.InteropServices.Marshal]::PtrToStringAuto(
//	    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
//	) | smtprelayd.exe -out C:\ProgramData\SMTPRelayd\secret.bin protect-secret
func protectSecret(outPath string) error {
	if outPath == "" {
		return fmt.Errorf("protect-secret: -out <file> is required")
	}
	line, err := readSecretLine(os.Stdin)
	if err != nil {
		return fmt.Errorf("protect-secret: reading stdin: %w", err)
	}
	if line == "" {
		return fmt.Errorf("protect-secret: no secret read from stdin")
	}
	ciphertext, err := config.ProtectMachineSecret([]byte(line))
	if err != nil {
		return fmt.Errorf("protect-secret: %w", err)
	}
	if err := os.WriteFile(outPath, ciphertext, 0o600); err != nil {
		return fmt.Errorf("protect-secret: %w", err)
	}
	fmt.Printf("smtprelayd: wrote DPAPI-protected secret to %s\n", outPath)
	fmt.Printf("smtprelayd: reference it in the configuration as dpapi:%s\n", outPath)
	return nil
}

// readSecretLine reads the first line from r, stripped of its line ending.
// A trailing newline with nothing before it, or no input at all, both read
// back as "", which protectSecret rejects rather than encrypting nothing.
func readSecretLine(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		return "", scanner.Err()
	}
	return scanner.Text(), nil
}
