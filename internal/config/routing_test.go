// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

import (
	"strings"
	"testing"
)

func loadErr(t *testing.T, body string) string {
	t.Helper()
	_, err := Load(write(t, body))
	if err == nil {
		t.Fatal("configuration was accepted but should have been refused")
	}
	return err.Error()
}

func TestDuplicateRouteDomainIsRefused(t *testing.T) {
	body := baseConfig + `
domains = ["partner.example"]

[[route]]
name = "partner"
host = "mail.partner.example"
auth = "none"
domains = ["partner.example"]
`
	if e := loadErr(t, body); !strings.Contains(e, "already routed") {
		t.Fatalf("unexpected error: %s", e)
	}
}

func TestOverlappingRouteSourcesAreRefused(t *testing.T) {
	body := baseConfig + `
sources = ["10.0.0.0/8"]

[[route]]
name = "partner"
host = "mail.partner.example"
auth = "none"
sources = ["10.10.5.0/24"]
`
	if e := loadErr(t, body); !strings.Contains(e, "overlaps") {
		t.Fatalf("unexpected error: %s", e)
	}
}

func TestRouteSourceWithHostBitsIsRefused(t *testing.T) {
	body := baseConfig + `
sources = ["10.10.5.7/24"]
`
	if e := loadErr(t, body); !strings.Contains(e, "host bits") {
		t.Fatalf("unexpected error: %s", e)
	}
}

// A source network overlapping a client CIDR is the intended way to move a
// subnet of an existing client onto another route, so it must load.
func TestRouteSourceMayOverlapClientCIDR(t *testing.T) {
	body := baseConfig + `
sources = ["10.10.5.128/25"]
`
	if _, err := Load(write(t, body)); err != nil {
		t.Fatalf("source overlapping a client CIDR was refused: %v", err)
	}
}

func TestClientCannotRaiseTheSizeCeiling(t *testing.T) {
	body := strings.Replace(baseConfig,
		`cidr = ["10.10.5.0/24"]`,
		"cidr = [\"10.10.5.0/24\"]\nmax_message_mb = 100", 1)
	if e := loadErr(t, body); !strings.Contains(e, "max_message_mb") {
		t.Fatalf("unexpected error: %s", e)
	}
}

// withRewrite inserts a rewrite sub-table into the client of baseConfig. It
// has to be spliced in rather than appended, because a table written after
// the route block would belong to the route.
func withRewrite(block string) string {
	return strings.Replace(baseConfig, "route = \"m365\"\n",
		"route = \"m365\"\n\n  [client.rewrite]\n"+block, 1)
}

func TestRewriteModeIfUnauthorizedNeedsAllowlist(t *testing.T) {
	body := withRewrite(`  mode = "if_unauthorized"
  envelope_from = "relay@example.at"
`)
	if e := loadErr(t, body); !strings.Contains(e, "allowed_senders") {
		t.Fatalf("unexpected error: %s", e)
	}
}

func TestRewriteHeaderFromMustAlign(t *testing.T) {
	body := withRewrite(`  mode = "force"
  envelope_from = "relay@example.at"
  header_from = "Relay <relay@other.example>"
`)
	if e := loadErr(t, body); !strings.Contains(e, "does not match") {
		t.Fatalf("unexpected error: %s", e)
	}
}
