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
