// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tokajer/smtprelayd/internal/config"
)

// parseFormatBlock turns one formatBlock output into a key/value map, so a
// test can assert on a specific field regardless of the column padding
// between the widest key and "=".
func parseFormatBlock(block string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(block, "\n") {
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// The configuration page must never render a resolved OAuth2 client secret,
// however it renders the field: formatRoutes goes through config.Secret's
// String(), never Value(), so this holds independently of the page-level
// TestConfigViewNeverRendersAResolvedSecret.
func TestFormatRoutesRedactsTheOAuth2ClientSecret(t *testing.T) {
	const secretEnv = "SMTPRELAYD_TEST_FORMAT_SECRET"
	const secretValue = "S3cretValueThatMustNeverAppear"
	t.Setenv(secretEnv, secretValue)

	cfg := testConfig(t, fmt.Sprintf(`
[[route]]
name = "oauth-route"
host = "smtp.office365.com"
auth = "xoauth2"
oauth2.tenant_id = "contoso.onmicrosoft.com"
oauth2.client_id = "00000000-0000-0000-0000-000000000000"
oauth2.client_secret = "${%s}"
oauth2.mailbox = "relay@contoso.onmicrosoft.com"
`, secretEnv))

	var route config.Route
	found := false
	for _, r := range cfg.Routes {
		if r.Name == "oauth-route" {
			route, found = r, true
		}
	}
	if !found || route.OAuth2.ClientSecret.Value() != secretValue {
		t.Fatal("test setup failed: the secret did not resolve to the expected value")
	}

	out := formatRoutes([]config.Route{route})
	if strings.Contains(out, secretValue) {
		t.Fatalf("the resolved secret leaked into formatRoutes output:\n%s", out)
	}
	fields := parseFormatBlock(out)
	if fields["oauth2.client_secret"] != "[redacted]" {
		t.Errorf(`oauth2.client_secret = %q, want "[redacted]":`+"\n%s", fields["oauth2.client_secret"], out)
	}
}

// Every toml-tagged field of config.Client, including the nested rewrite.*
// and bounce.notify fields the hand-written formatClients used to leave out,
// must reach the page: an operator reading this view has no other way to
// see what a client is actually configured with.
func TestFormatClientsRendersEveryField(t *testing.T) {
	c := config.Client{
		Name: "printers", CIDR: []string{"10.10.5.0/24"}, Route: "m365",
		MaxMessageMB: 10, MaxRecipients: 50, RateLimitPerMin: 30, MaxConnections: 4,
		Rewrite: config.Rewrite{
			Mode:           "static",
			AllowedSenders: []string{"a@b.at"},
			EnvelopeFrom:   "relay@example.at",
			HeaderFrom:     "Printers <relay@example.at>",
			ReplyTo:        "ops@example.at",
		},
		Bounce: config.ClientBounce{Notify: []string{"printer-admins@example.at"}},
	}

	fields := parseFormatBlock(formatClients([]config.Client{c}))

	for key, want := range map[string]string{
		"cidr":                    "10.10.5.0/24",
		"route":                   "m365",
		"max_message_mb":          "10",
		"max_recipients":          "50",
		"rate_limit_per_min":      "30",
		"max_connections":         "4",
		"rewrite.mode":            "static",
		"rewrite.allowed_senders": "a@b.at",
		"rewrite.envelope_from":   "relay@example.at",
		"rewrite.header_from":     "Printers <relay@example.at>",
		"rewrite.reply_to":        "ops@example.at",
		"bounce.notify":           "printer-admins@example.at",
	} {
		got, ok := fields[key]
		if !ok {
			t.Errorf("formatClients output is missing key %q", key)
			continue
		}
		if got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}
