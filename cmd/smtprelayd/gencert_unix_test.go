// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package main

import (
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/tokajer/smtprelayd/internal/config"
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

// The key's group comes from whatever owns the configuration file. On a
// packaged install that is the service's own group and all is well; on a
// hand-made one it can be a group every local account belongs to, and the
// command used to report that outcome in words indistinguishable from the
// correct one. Naming the group is the only thing that tells the two apart.
func TestGenCertNamesTheGroupItWidenedTheKeyTo(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "tls")
	path := writeConfig(t, tlsConfigBody(t, certDir))

	var out strings.Builder
	if err := genCert(path, false, 0, &out); err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	gid := st.Sys().(*syscall.Stat_t).Gid
	want := strconv.FormatUint(uint64(gid), 10)
	if g, err := user.LookupGroupId(want); err == nil && g.Name != "" {
		want = g.Name
	}

	if !strings.Contains(out.String(), "readable by group "+want) {
		t.Errorf("the output does not name the group the key was widened to (%s):\n%s", want, out.String())
	}
}

// What gen-cert writes has to pass the key check serve applies before it
// loads the pair, or the documented first-start sequence ends in a refusal;
// and the same key made world-readable has to be refused there and by check.
func TestLoadCertificateChecksTheKeyGenCertWrote(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "tls")
	path := writeConfig(t, tlsConfigBody(t, certDir))
	if err := genCert(path, false, 0, io.Discard); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("the configuration does not load after gen-cert: %v", err)
	}
	if _, err := loadCertificate(cfg); err != nil {
		t.Fatalf("the key gen-cert wrote was refused: %v", err)
	}

	if err := os.Chmod(cfg.TLS.KeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = loadCertificate(cfg)
	if err == nil {
		t.Fatal("a world-readable key was loaded")
	}
	if !strings.Contains(err.Error(), "chmod 0640") {
		t.Errorf("the refusal does not name the fix: %v", err)
	}
	// check has to refuse what serve refuses, or it passes a configuration
	// the service then will not start with.
	err = cmdCheck(cmdOptions{configPath: path})
	if err == nil || !strings.Contains(err.Error(), "chmod 0640") {
		t.Errorf("check with a world-readable key: %v, want the key refusal", err)
	}
}
