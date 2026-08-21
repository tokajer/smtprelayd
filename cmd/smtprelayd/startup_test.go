// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tokajer/smtprelayd/internal/config"
)

// A configuration that fails validation (a typo'd service.timezone, say)
// must still leave a trace an operator can find in the data directory, not
// only on stderr.
func TestLogStartupFailureWritesToDataDir(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Service: config.Service{DataDir: dir}}

	logStartupFailure("/etc/smtprelayd/smtprelayd.toml", cfg, errors.New("service.timezone: unsupported timezone \"sEurope/Vienna\""))

	b, err := os.ReadFile(filepath.Join(dir, "smtprelayd-error.log"))
	if err != nil {
		t.Fatalf("smtprelayd-error.log was not written: %v", err)
	}
	if !strings.Contains(string(b), "sEurope/Vienna") {
		t.Fatalf("error log does not mention the failure: %s", b)
	}
}

// A nil Config means config.Load failed before any field, including
// data_dir, was known — there is nowhere safe to write, so this must not
// panic and must not create anything.
func TestLogStartupFailureWithNilConfigIsANoop(t *testing.T) {
	logStartupFailure("/etc/smtprelayd/smtprelayd.toml", nil, errors.New("config: unexpected EOF"))
}
