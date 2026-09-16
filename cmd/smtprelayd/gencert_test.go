// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package main

import (
	"crypto/tls"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tokajer/smtprelayd/internal/config"
)

// writeConfig puts a minimal configuration on disk with the mode
// config.CheckConfigFile insists on.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "smtprelayd.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// tlsConfigBody is a configuration whose [tls] paths do not exist yet, which
// is exactly the state gen-cert is for: Validate refuses it, because a
// listener uses TLS and the certificate it names is absent.
func tlsConfigBody(t *testing.T, certDir string) string {
	t.Helper()
	return `
[service]
data_dir = "` + filepath.ToSlash(t.TempDir()) + `"
hostname = "relay.internal.example.at"

[[listener]]
name = "smtps"
address = "127.0.0.1:20465"
tls = "implicit"

[tls]
cert_file = "` + filepath.ToSlash(filepath.Join(certDir, "relay.crt")) + `"
key_file  = "` + filepath.ToSlash(filepath.Join(certDir, "relay.key")) + `"

[[client]]
name = "local-app"
cidr = ["127.0.0.1/32"]
route = "r"

[[route]]
name = "r"
host = "127.0.0.1"
port = 12525
tls = "none"
auth = "none"
default = true
`
}

// The point of the command: a configuration that does not validate *because*
// the certificate is missing must still be actionable, or gen-cert cannot do
// the one job it exists for.
func TestGenCertWorksOnAConfigThatDoesNotValidateYet(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "tls")
	path := writeConfig(t, tlsConfigBody(t, certDir))

	// Confirm the premise rather than assume it.
	if _, err := config.Load(path); err == nil {
		t.Fatal("setup: the configuration was expected not to validate yet")
	}

	var out strings.Builder
	if err := genCert(path, false, &out); err != nil {
		t.Fatalf("gen-cert: %v", err)
	}

	certFile := filepath.Join(certDir, "relay.crt")
	keyFile := filepath.Join(certDir, "relay.key")
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("the written pair does not load the way the listener loads it: %v", err)
	}
	// The whole configuration must now validate, which is the outcome the
	// operator actually wanted.
	if _, err := config.Load(path); err != nil {
		t.Fatalf("configuration still does not validate after gen-cert: %v", err)
	}
	if !strings.Contains(out.String(), "does not validate yet") {
		t.Error("the warning about the invalid configuration should be shown")
	}
}

func TestGenCertWritesARestrictedKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not govern access on Windows; the data directory DACL does")
	}
	certDir := filepath.Join(t.TempDir(), "tls")
	path := writeConfig(t, tlsConfigBody(t, certDir))
	if err := genCert(path, false, io.Discard); err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(filepath.Join(certDir, "relay.key"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Errorf("key mode = %04o, want 0600", mode)
	}
}

// Refusing by default is the guard that matters: these paths routinely hold
// a key issued by a real CA, and overwriting one is not recoverable.
func TestGenCertRefusesToOverwriteWithoutForce(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "tls")
	path := writeConfig(t, tlsConfigBody(t, certDir))
	if err := genCert(path, false, io.Discard); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(certDir, "relay.crt"))
	if err != nil {
		t.Fatal(err)
	}

	err = genCert(path, false, io.Discard)
	if err == nil {
		t.Fatal("a second gen-cert without -force must refuse")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Errorf("error should say it is refusing to overwrite, got %v", err)
	}
	after, err := os.ReadFile(filepath.Join(certDir, "relay.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("the existing certificate was modified despite the refusal")
	}
}

func TestGenCertForceReplacesAndRestoresTheKeyMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not govern access on Windows")
	}
	certDir := filepath.Join(t.TempDir(), "tls")
	path := writeConfig(t, tlsConfigBody(t, certDir))
	if err := genCert(path, false, io.Discard); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(certDir, "relay.key")
	before, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	// os.WriteFile applies its mode only when it creates the file, so a key
	// loosened by hand would otherwise stay loose through a -force run.
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := genCert(path, true, io.Discard); err != nil {
		t.Fatalf("gen-cert -force: %v", err)
	}
	after, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) == string(after) {
		t.Error("-force did not replace the key")
	}
	st, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o600 {
		t.Errorf("key mode after -force = %04o, want 0600", mode)
	}
}

// With no [tls] block there is nowhere to write, and inventing a path would
// produce files the configuration does not point at.
func TestGenCertWithoutTLSPathsIsRefused(t *testing.T) {
	path := writeConfig(t, `
[service]
data_dir = "`+filepath.ToSlash(t.TempDir())+`"
hostname = "relay.internal.example.at"

[[listener]]
name = "smtp"
address = "127.0.0.1:20025"
tls = "none"

[[client]]
name = "local-app"
cidr = ["127.0.0.1/32"]
route = "r"

[[route]]
name = "r"
host = "127.0.0.1"
port = 12525
tls = "none"
auth = "none"
default = true
`)
	err := genCert(path, false, io.Discard)
	if err == nil {
		t.Fatal("gen-cert without [tls] paths must be refused")
	}
	if !strings.Contains(err.Error(), "cert_file") {
		t.Errorf("error should name the missing setting, got %v", err)
	}
}

// A file that cannot be decoded at all yields no Config, so there is no
// [tls] block to act on and the decode error is what the operator needs.
func TestGenCertOnAnUndecodableConfigReturnsTheLoadError(t *testing.T) {
	path := writeConfig(t, "this is not toml {{{")
	if err := genCert(path, false, io.Discard); err == nil {
		t.Fatal("an undecodable configuration must be reported")
	}
}

func TestCertHostsSkipsWildcardBindsAndDeduplicates(t *testing.T) {
	cfg := &config.Config{
		Service: config.Service{Hostname: "relay.internal.example.at"},
		Listeners: []config.Listener{
			{Name: "smtp", Address: "0.0.0.0:25"},
			{Name: "smtps", Address: "[::]:465"},
			{Name: "submission", Address: "10.10.5.1:587"},
			{Name: "dup", Address: "10.10.5.1:588"},
		},
	}
	got := certHosts(cfg)
	want := []string{"relay.internal.example.at", "10.10.5.1", "10.10.5.1", "localhost", "127.0.0.1", "::1"}
	if len(got) != len(want) {
		t.Fatalf("certHosts() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("certHosts() = %v, want %v", got, want)
		}
	}
	// A wildcard bind is not a name any client asks for, so it must not
	// reach the SAN list.
	for _, h := range got {
		if h == "0.0.0.0" || h == "::" {
			t.Errorf("wildcard bind %q leaked into the SAN list", h)
		}
	}
}
