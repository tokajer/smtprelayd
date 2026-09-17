// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A secret file is only as protected as the directory it sits in: a
// group-writable parent lets another account unlink it and put its own file
// there. CheckConfigFile was fixed for exactly this; checkSecretFile was left
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

	if err := checkSecretFile(path); err != nil {
		t.Fatalf("a 0600 secret in a 0700 directory was rejected: %v", err)
	}

	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	err := checkSecretFile(path)
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
	if err := checkSecretFile(path); err == nil {
		t.Fatal("a world-readable secret was accepted")
	}
}

// checkTrusted refuses a symlink rather than following it: service.data_dir
// and the directory the binary runs from are checked at startup by a process
// that may be privileged enough to bind port 25, and a link lets whoever can
// replace it point that process somewhere else. The writable-directory branch
// is covered through checkSecretFile above; this branch and CheckDir itself
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
