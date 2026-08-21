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
	dir := filepath.Dir(configPath)
	if cfg, err := config.Load(configPath); err == nil {
		dir = cfg.Service.DataDir
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
// docs/EXPLOIT-SURFACE.md §1 gives for checking it at startup: this is the
// one function in the tree that recurses into the data directory instead of
// only reading or ACLing it, so a junction planted at this path — before a
// fresh install or after an operator manually recreated it without the
// ACL — matters most exactly here, run as SYSTEM with no further
// confirmation. A missing directory is not an error: purge-datadir may run
// against a data directory that never existed or was already removed.
func purgeDataDir(configPath string) error {
	dir := filepath.Dir(configPath)
	if cfg, err := config.Load(configPath); err == nil {
		dir = cfg.Service.DataDir
	}
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
