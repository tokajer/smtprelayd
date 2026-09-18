// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package main

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// This lives in its own file rather than behind a runtime skip. syscall.Stat_t
// does not exist on Windows, so a `runtime.GOOS == "windows"` check never gets
// to run: the package fails to compile first, which took every test in
// cmd/smtprelayd with it and went unnoticed because CI only builds on Linux.
// A build tag is the gate a platform-specific type needs.

// The service must be able to read the key it will be started with. On Unix
// that means the configuration file's group, since the package gives
// /etc/smtprelayd to root:smtprelayd and the command runs as root.
func TestGenCertGivesTheKeyTheConfigurationsGroup(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "tls")
	path := writeConfig(t, tlsConfigBody(t, certDir))
	if err := genCert(path, false, 0, io.Discard); err != nil {
		t.Fatal(err)
	}

	cfgInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	wantGid := cfgInfo.Sys().(*syscall.Stat_t).Gid

	keyFile := filepath.Join(certDir, "relay.key")
	for _, tc := range []struct {
		path     string
		wantMode os.FileMode
	}{
		{certDir, 0o750},
		{keyFile, 0o640},
	} {
		fi, err := os.Stat(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if gid := fi.Sys().(*syscall.Stat_t).Gid; gid != wantGid {
			t.Errorf("%s has gid %d, want the configuration's %d", tc.path, gid, wantGid)
		}
		if mode := fi.Mode().Perm(); mode != tc.wantMode {
			t.Errorf("%s has mode %04o, want %04o", tc.path, mode, tc.wantMode)
		}
	}
}
