// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package fsmode

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRestrictFileClosesAWorldReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RestrictFile(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode is %04o, want 0600", fi.Mode().Perm())
	}
}

// The callers restrict sidecars their dependency may not have created yet
// (a -wal file on a fresh database), so a missing file is not a failure.
func TestRestrictFileIgnoresAMissingFile(t *testing.T) {
	if err := RestrictFile(filepath.Join(t.TempDir(), "history.db-wal")); err != nil {
		t.Fatalf("a missing file was reported as an error: %v", err)
	}
}
