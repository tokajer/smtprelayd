// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package ostrust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A secret file is only as protected as the directory it sits in: a
// group-writable parent lets another account unlink it and put its own file
// there. CheckConfigFile was fixed for exactly this; CheckSecretFile was left
// behind until 2026-08-11.
func TestCheckSecretFileRejectsWritableDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "client_secret")
	if err := os.WriteFile(path, []byte("s3cr3t"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := CheckSecretFile(path); err != nil {
		t.Fatalf("a 0600 secret in a 0700 directory was rejected: %v", err)
	}

	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	err := CheckSecretFile(path)
	if err == nil {
		t.Fatal("a secret in a group-writable directory was accepted")
	}
	if !strings.Contains(err.Error(), "directory of secret file") {
		t.Fatalf("failed for an unrelated reason: %v", err)
	}
}

func TestCheckSecretFileStillRejectsAReadableSecret(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "client_secret")
	if err := os.WriteFile(path, []byte("s3cr3t"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckSecretFile(path); err == nil {
		t.Fatal("a world-readable secret was accepted")
	}
}

// checkTrusted refuses a symlink rather than following it: service.data_dir
// and the directory the binary runs from are checked at startup by a process
// that may be privileged enough to bind port 25, and a link lets whoever can
// replace it point that process somewhere else. The writable-directory branch
// is covered through CheckSecretFile above; this branch and CheckDir itself
// had no test, so either could be deleted with the suite green.
//
// The ownership branch is not covered here: it needs a directory owned by
// another uid, which an unprivileged test run cannot create.
func TestCheckDirRefusesASymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "data")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(real); err != nil {
		t.Fatalf("a 0700 directory owned by this user was rejected: %v", err)
	}

	link := filepath.Join(base, "data-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	err := CheckDir(link)
	if err == nil {
		t.Fatal("CheckDir followed a symlink to the data directory")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("failed for an unrelated reason: %v", err)
	}
}

// writeKey puts a key file of mode perm in a fresh 0750 directory, the
// layout gen-cert leaves.
func writeKey(t *testing.T, perm os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tls")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "relay.key")
	if err := os.WriteFile(path, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	// WriteFile's mode passes through the umask; Chmod does not.
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
	return path
}

// gen-cert writes the key 0600 and then widens it to 0640 with the
// configuration file's group so the service account can read it; both have
// to start. Anything that lets the group write, or anyone else at all, must
// not: the key is what lets a device trust it is talking to this relay.
func TestCheckKeyFileModes(t *testing.T) {
	for _, tc := range []struct {
		perm os.FileMode
		ok   bool
	}{
		{0o600, true},
		{0o640, true},
		{0o400, true},
		{0o644, false},
		{0o660, false},
		{0o604, false},
		{0o601, false},
	} {
		err := CheckKeyFile(writeKey(t, tc.perm))
		switch {
		case tc.ok && err != nil:
			t.Errorf("mode %04o was refused: %v", tc.perm, err)
		case !tc.ok && err == nil:
			t.Errorf("mode %04o was accepted", tc.perm)
		case !tc.ok && !strings.Contains(err.Error(), "chmod 0640"):
			t.Errorf("mode %04o: the error does not name the fix: %v", tc.perm, err)
		}
	}
}

func TestCheckKeyFileRefusesASymlink(t *testing.T) {
	real := writeKey(t, 0o600)
	link := filepath.Join(filepath.Dir(real), "relay-link.key")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	err := CheckKeyFile(link)
	if err == nil {
		t.Fatal("a symlinked key was accepted")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("failed for an unrelated reason: %v", err)
	}
}

// A group-writable directory lets another account replace a key whose own
// mode is sound.
func TestCheckKeyFileRefusesAWritableDirectory(t *testing.T) {
	path := writeKey(t, 0o640)
	if err := os.Chmod(filepath.Dir(path), 0o770); err != nil {
		t.Fatal(err)
	}
	err := CheckKeyFile(path)
	if err == nil {
		t.Fatal("a key in a group-writable directory was accepted")
	}
	if !strings.Contains(err.Error(), "directory of TLS key") {
		t.Fatalf("failed for an unrelated reason: %v", err)
	}
}

// The directory alone used to be checked, so a binary anyone could rewrite
// passed as long as it sat in a sound directory.
func TestCheckExecutableRefusesAWritableBinary(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "smtprelayd")
	if err := os.WriteFile(exe, []byte("#!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(exe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckExecutable(exe); err != nil {
		t.Fatalf("a 0755 binary in a 0755 directory was refused: %v", err)
	}

	if err := os.Chmod(exe, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := CheckExecutable(exe); err == nil {
		t.Fatal("a group-writable binary was accepted")
	}

	if err := os.Chmod(exe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := CheckExecutable(exe); err == nil {
		t.Fatal("a binary in a world-writable directory was accepted")
	}
}
