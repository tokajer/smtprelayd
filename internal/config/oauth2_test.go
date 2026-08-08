// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

import (
	"strings"
	"testing"
)

const oauthConfig = `
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
host = "smtp.office365.com"
auth = "xoauth2"

  [route.oauth2]
  tenant_id = "contoso.onmicrosoft.com"
  client_id = "00000000-0000-0000-0000-000000000000"
  client_secret = "${SMTPRELAYD_TEST_SECRET}"
  mailbox = "relay@example.at"
`

func loadOAuth(t *testing.T, body string) (*Config, error) {
	t.Helper()
	t.Setenv("SMTPRELAYD_TEST_SECRET", "s3cret")
	return Load(write(t, body))
}

func TestXOAUTH2ScopeDefaults(t *testing.T) {
	cfg, err := loadOAuth(t, oauthConfig)
	if err != nil {
		t.Fatalf("configuration rejected: %v", err)
	}
	if got := cfg.Routes[0].OAuth2.Scope; got != DefaultScope {
		t.Fatalf("scope = %q, want %q", got, DefaultScope)
	}
}

func TestXOAUTH2RejectsUnsafeValues(t *testing.T) {
	cases := map[string][2]string{
		"tenant with a path segment": {
			`tenant_id = "contoso.onmicrosoft.com"`, `tenant_id = "contoso/../evil"`},
		"mailbox with a separator": {
			`mailbox = "relay@example.at"`, `mailbox = "relay\u0001auth=Bearer x@example.at"`},
		"mailbox that is not an address": {
			`mailbox = "relay@example.at"`, `mailbox = "relay"`},
		"scope for the wrong resource": {
			`mailbox = "relay@example.at"`, "mailbox = \"relay@example.at\"\n  scope = \"api://internal\""},
		"malformed secret expiry": {
			`mailbox = "relay@example.at"`, "mailbox = \"relay@example.at\"\n  secret_expires = \"01.02.2027\""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(oauthConfig, c[0], c[1], 1)
			if _, err := loadOAuth(t, body); err == nil {
				t.Fatal("configuration was accepted")
			}
		})
	}
}

func TestXOAUTH2RequiresAMailbox(t *testing.T) {
	body := strings.Replace(oauthConfig, `  mailbox = "relay@example.at"`, "", 1)
	_, err := loadOAuth(t, body)
	if err == nil {
		t.Fatal("xoauth2 was accepted without a mailbox")
	}
	if !strings.Contains(err.Error(), "mailbox") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSecretExpiryIsReadable(t *testing.T) {
	body := strings.Replace(oauthConfig, `  mailbox = "relay@example.at"`,
		"  mailbox = \"relay@example.at\"\n  secret_expires = \"2027-02-01\"", 1)
	cfg, err := loadOAuth(t, body)
	if err != nil {
		t.Fatalf("configuration rejected: %v", err)
	}
	exp, ok := cfg.Routes[0].OAuth2.SecretExpiry()
	if !ok {
		t.Fatal("secret_expires was not readable")
	}
	if exp.Year() != 2027 {
		t.Fatalf("expiry = %v", exp)
	}
}
