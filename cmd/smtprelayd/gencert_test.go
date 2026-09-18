// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
	if err := genCert(path, false, 0, &out); err != nil {
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

// 0640, not 0600: the key has to stay unreadable to other local accounts --
// it is the property that matters -- while still being readable by the group
// the service runs under, which is what ShareWithGroupOf widens it to.
func TestGenCertWritesARestrictedKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not govern access on Windows; the data directory DACL does")
	}
	certDir := filepath.Join(t.TempDir(), "tls")
	path := writeConfig(t, tlsConfigBody(t, certDir))
	if err := genCert(path, false, 0, io.Discard); err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(filepath.Join(certDir, "relay.key"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := st.Mode().Perm(); mode != 0o640 {
		t.Errorf("key mode = %04o, want 0640", mode)
	}
	if mode := st.Mode().Perm(); mode&0o007 != 0 {
		t.Errorf("key mode %04o grants access to other accounts", mode)
	}
}

// Refusing by default is the guard that matters: these paths routinely hold
// a key issued by a real CA, and overwriting one is not recoverable.
func TestGenCertRefusesToOverwriteWithoutForce(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "tls")
	path := writeConfig(t, tlsConfigBody(t, certDir))
	if err := genCert(path, false, 0, io.Discard); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(certDir, "relay.crt"))
	if err != nil {
		t.Fatal(err)
	}

	err = genCert(path, false, 0, io.Discard)
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
	if err := genCert(path, false, 0, io.Discard); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(certDir, "relay.key")
	before, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	// os.WriteFile applies its mode only when it creates the file, so a key
	// loosened by hand would otherwise stay world-readable through a -force
	// run.
	if err := os.Chmod(keyFile, 0o666); err != nil {
		t.Fatal(err)
	}

	if err := genCert(path, true, 0, io.Discard); err != nil {
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
	if mode := st.Mode().Perm(); mode != 0o640 {
		t.Errorf("key mode after -force = %04o, want 0640", mode)
	}
	if mode := st.Mode().Perm(); mode&0o007 != 0 {
		t.Errorf("key mode %04o after -force grants access to other accounts", mode)
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
	err := genCert(path, false, 0, io.Discard)
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
	if err := genCert(path, false, 0, io.Discard); err == nil {
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
			// Same address on a second listener, and the hostname again: a
			// SAN list that repeats an entry is confusing in the printed
			// output and pointless in the certificate.
			{Name: "dup", Address: "10.10.5.1:588"},
			{Name: "loop", Address: "127.0.0.1:2525"},
		},
	}
	got := certHosts(cfg)
	want := []string{"relay.internal.example.at", "10.10.5.1", "127.0.0.1", "localhost", "::1"}
	if len(got) != len(want) {
		t.Fatalf("certHosts() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("certHosts() = %v, want %v", got, want)
		}
	}
	// A wildcard bind is not a name any client asks for.
	for _, h := range got {
		if h == "0.0.0.0" || h == "::" {
			t.Errorf("wildcard bind %q leaked into the SAN list", h)
		}
	}
}

// The metrics endpoint serves this same certificate when it binds beyond
// loopback, so a certificate without that name fails hostname verification
// for the monitoring system while working fine for mail.
func TestCertHostsIncludesAPublicMetricsAddress(t *testing.T) {
	cfg := &config.Config{
		Service:   config.Service{Hostname: "relay.internal.example.at"},
		Listeners: []config.Listener{{Name: "smtp", Address: "0.0.0.0:25"}},
		Metrics:   config.Metrics{Enabled: true, Address: "10.0.0.5:9025"},
	}
	got := certHosts(cfg)
	found := false
	for _, h := range got {
		if h == "10.0.0.5" {
			found = true
		}
	}
	if !found {
		t.Fatalf("certHosts() = %v, want it to include the metrics address", got)
	}
}

// Metrics disabled contributes nothing, and a loopback metrics address is
// already covered by the constants.
func TestCertHostsIgnoresDisabledMetrics(t *testing.T) {
	cfg := &config.Config{
		Service: config.Service{Hostname: "relay.internal.example.at"},
		Metrics: config.Metrics{Enabled: false, Address: "10.0.0.5:9025"},
	}
	for _, h := range certHosts(cfg) {
		if h == "10.0.0.5" {
			t.Fatalf("a disabled metrics address reached the SAN list: %v", certHosts(cfg))
		}
	}
}

// -days is what makes the expiry warning testable: without it the only
// certificate this command can produce is 825 days out, and nothing inside
// the 30-day window can be reached without hand-building a PEM.
func TestGenCertDaysSetsTheValidity(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "tls")
	path := writeConfig(t, tlsConfigBody(t, certDir))
	if err := genCert(path, false, 20, io.Discard); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(certDir, "relay.crt"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		t.Fatal("certificate did not decode")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	days := int(time.Until(c.NotAfter).Hours() / 24)
	if days != 19 && days != 20 {
		t.Errorf("certificate is valid for %d days, want 20", days)
	}
}

func TestGenCertRejectsAnOutOfRangeDays(t *testing.T) {
	certDir := filepath.Join(t.TempDir(), "tls")
	path := writeConfig(t, tlsConfigBody(t, certDir))
	for _, days := range []int{-1, maxValidityDays + 1} {
		if err := genCert(path, false, days, io.Discard); err == nil {
			t.Errorf("-days %d must be refused", days)
		}
	}
	// Nothing may have been written by a refused run.
	if _, err := os.Stat(filepath.Join(certDir, "relay.crt")); err == nil {
		t.Error("a refused -days still wrote a certificate")
	}
}
