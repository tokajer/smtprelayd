// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const baseConfig = `
[service]
data_dir = "/tmp/smtprelayd-test"

[[listener]]
name = "smtp"
address = "127.0.0.1:2525"
tls = "none"

[[client]]
name = "printers"
cidr = ["10.10.5.0/24"]
route = "m365"

[[route]]
name = "m365"
default = true
host = "smtp.example"
auth = "none"
`

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "smtprelayd.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadBaseline(t *testing.T) {
	if _, err := Load(write(t, baseConfig)); err != nil {
		t.Fatalf("baseline configuration rejected: %v", err)
	}
}

func TestOpenRelayIsRefused(t *testing.T) {
	body := strings.Replace(baseConfig, `address = "127.0.0.1:2525"`, `address = "0.0.0.0:2525"`, 1)
	body = body[:strings.Index(body, "[[client]]")] + body[strings.Index(body, "[[route]]"):]
	_, err := Load(write(t, body))
	if err == nil {
		t.Fatal("a public listener with no client allowlist was accepted")
	}
	if !strings.Contains(err.Error(), "open relay") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOverlappingCIDRIsRefused(t *testing.T) {
	body := baseConfig + `
[[client]]
name = "overlap"
cidr = ["10.10.5.128/25"]
route = "m365"
`
	_, err := Load(write(t, body))
	if err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("overlapping CIDRs were accepted: %v", err)
	}
}

func TestLiteralSecretIsRefused(t *testing.T) {
	body := baseConfig + `
[[route]]
name = "partner"
host = "mail.partner.example"
auth = "plain"

  [route.credentials]
  username = "relay@example.at"
  password = "hunter2"
`
	_, err := Load(write(t, body))
	if err == nil || !strings.Contains(err.Error(), "never a literal value") {
		t.Fatalf("a plaintext password in the configuration was accepted: %v", err)
	}
}

func TestSecretNeverFormats(t *testing.T) {
	t.Setenv("SMTPRELAYD_TEST_SECRET", "topsecret")
	body := baseConfig + `
[[route]]
name = "partner"
host = "mail.partner.example"
auth = "login"

  [route.credentials]
  username = "relay@example.at"
  password = "${SMTPRELAYD_TEST_SECRET}"
`
	cfg, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := cfg.Route("partner")
	if r.Credentials.Password.Value() != "topsecret" {
		t.Fatal("secret was not resolved from the environment")
	}
	for _, rendered := range []string{
		strings.TrimSpace(r.Credentials.Password.String()),
		fmt.Sprintf("%v", r.Credentials.Password),
		fmt.Sprintf("%s", r.Credentials.Password),
		fmt.Sprintf("%#v", r.Credentials.Password),
		fmt.Sprintf("%v", r.Credentials),
	} {
		if strings.Contains(rendered, "topsecret") {
			t.Fatalf("secret leaked through formatting: %s", rendered)
		}
	}
}

func TestUnknownKeyIsRefused(t *testing.T) {
	body := baseConfig + "\n[queue]\ninsecure_skip_verify = true\n"
	if _, err := Load(write(t, body)); err == nil {
		t.Fatal("an unknown key was silently ignored")
	}
}

func TestOutboundTLSCannotBeWeakened(t *testing.T) {
	body := strings.Replace(baseConfig, `auth = "none"`, "auth = \"none\"\nmin_tls = \"1.0\"", 1)
	if _, err := Load(write(t, body)); err == nil {
		t.Fatal("an outbound TLS minimum below 1.2 was accepted")
	}
}

func TestCleartextRouteIsAccepted(t *testing.T) {
	body := strings.Replace(baseConfig, `auth = "none"`, "auth = \"none\"\ntls = \"none\"", 1)
	cfg, err := Load(write(t, body))
	if err != nil {
		t.Fatalf("tls none was rejected: %v", err)
	}
	if cfg.Routes[0].TLS != "none" {
		t.Fatalf("tls none was rewritten to %q", cfg.Routes[0].TLS)
	}
	if cfg.Routes[0].MinTLS != "" {
		t.Fatalf("min_tls defaulted to %q on a route with no handshake", cfg.Routes[0].MinTLS)
	}
}

func TestCleartextRouteRefusesAuth(t *testing.T) {
	for _, auth := range []string{"plain", "login", "xoauth2"} {
		body := strings.Replace(baseConfig, `auth = "none"`,
			fmt.Sprintf("auth = %q\ntls = \"none\"", auth), 1)
		if _, err := Load(write(t, body)); err == nil {
			t.Fatalf("auth %s was accepted on a cleartext route", auth)
		}
	}
}

func TestCleartextRouteRefusesHandshakeSettings(t *testing.T) {
	for _, key := range []string{`min_tls = "1.2"`, `ca_pin = "ab"`} {
		body := strings.Replace(baseConfig, `auth = "none"`,
			"auth = \"none\"\ntls = \"none\"\n"+key, 1)
		if _, err := Load(write(t, body)); err == nil {
			t.Fatalf("%s was silently ignored on a cleartext route", key)
		}
	}
}
