// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package logging

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The log file carries every queue ID, sender and recipient the relay handled,
// so it is not a file other local accounts may read. lumberjack creates 0644
// and copies the current file's mode onto each rotation, which is why the file
// is created here before lumberjack ever opens it.
func TestLogFileIsCreated0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not the access control mechanism on Windows")
	}
	path := filepath.Join(t.TempDir(), "smtprelayd.log")

	log, closer, err := New(Options{Level: slog.LevelInfo, File: path, MaxSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	log.Info("starting")
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("log file mode is %04o, want 0600", got)
	}
}

// A file an earlier version left world-readable must be restricted on the next
// start, not only a freshly created one.
func TestExistingLogFileIsRestricted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not the access control mechanism on Windows")
	}
	path := filepath.Join(t.TempDir(), "smtprelayd.log")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, closer, err := New(Options{Level: slog.LevelInfo, File: path})
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("a pre-existing 0644 log file stayed at %04o", got)
	}
}

// Rotation is the one thing the lumberjack dependency is there for, and the
// module path changed on 2026-08-12. Asserting that a backup file appears
// proves the new module is wired up and doing its job, rather than merely
// compiling.
func TestRotationProducesABackupFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smtprelayd.log")

	// MaxSize is in megabytes and is the smallest rotation trigger available,
	// so the file has to be pushed past a megabyte to see one.
	log, closer, err := New(Options{Level: slog.LevelInfo, File: path, MaxSizeMB: 1, MaxBackups: 3})
	if err != nil {
		t.Fatal(err)
	}
	filler := strings.Repeat("x", 4096)
	for i := 0; i < 400; i++ {
		log.Info("filling", "n", i, "pad", filler)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	backups := 0
	for _, e := range entries {
		if e.Name() != "smtprelayd.log" {
			backups++
		}
	}
	if backups == 0 {
		t.Fatalf("no rotated file appeared; directory holds only %v", entries)
	}
}

// Redaction lives in the handler rather than at each call site so that a new
// call site cannot forget it. That only holds if it survives the writer setup.
func TestSecretsAreRedactedInTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smtprelayd.log")
	log, closer, err := New(Options{Level: slog.LevelInfo, File: path})
	if err != nil {
		t.Fatal(err)
	}
	log.Info("token request", "client_secret", "s3cr3t", "authorization", "Bearer abc", "route", "m365")
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "s3cr3t") || strings.Contains(string(b), "Bearer abc") {
		t.Fatalf("a secret reached the log file: %s", b)
	}

	var line map[string]any
	if err := json.Unmarshal(b, &line); err != nil {
		t.Fatalf("log line is not JSON: %v (%s)", err, b)
	}
	if line["client_secret"] != Redacted || line["authorization"] != Redacted {
		t.Fatalf("expected both to be %q, got %v", Redacted, line)
	}
	if line["route"] != "m365" {
		t.Fatalf("a non-secret attribute was redacted: %v", line)
	}
}
