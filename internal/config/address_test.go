// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

import (
	"strings"
	"testing"
)

func TestValidAddressRejectsInjection(t *testing.T) {
	bad := []string{
		"",
		"nobody",
		"nobody@",
		"@example.at",
		"a b@example.at",
		"a@example.at\r\nBcc: victim@example.at",
		"a@example.at\n",
		"a@example.at\x00",
		"a@example.at\x7f",
		"a@localhost",      // no dot: not a routable domain
		"a@[192.0.2.1]",    // address literals are deliberately refused
		"\"a\"@example.at", // quoted local parts are not accepted
		"a<b@example.at",   // could escape an angle-addr
		strings.Repeat("x", 65) + "@example.at",
		"a@" + strings.Repeat("x", 250) + ".example.at",
	}
	for _, s := range bad {
		if ValidAddress(s) {
			t.Errorf("ValidAddress(%q) = true, want false", s)
		}
	}
	for _, s := range []string{"a@example.at", "first.last+tag@sub.example.at"} {
		if !ValidAddress(s) {
			t.Errorf("ValidAddress(%q) = false, want true", s)
		}
	}
}

func TestValidDomain(t *testing.T) {
	for _, s := range []string{"", "example", ".example.at", "example.at.", "ex..at", "ex_a.at", "ex am.at"} {
		if ValidDomain(s) {
			t.Errorf("ValidDomain(%q) = true, want false", s)
		}
	}
	for _, s := range []string{"example.at", "a-b.sub.example.at"} {
		if !ValidDomain(s) {
			t.Errorf("ValidDomain(%q) = false, want true", s)
		}
	}
}

func TestSplitMailboxRefusesUnquotableDisplayNames(t *testing.T) {
	bad := []string{
		`Drucker" <relay@example.at>`,
		`Dru\ker <relay@example.at>`,
		"Dru\x01cker <relay@example.at>",
		"Drucker <relay@example.at",
		"Drucker <>",
		"Drucker <not-an-address>",
		strings.Repeat("n", 129) + " <relay@example.at>",
	}
	for _, s := range bad {
		if _, _, ok := SplitMailbox(s); ok {
			t.Errorf("SplitMailbox(%q) accepted", s)
		}
	}

	display, addr, ok := SplitMailbox("Printer Vienna <relay@example.at>")
	if !ok || display != "Printer Vienna" || addr != "relay@example.at" {
		t.Fatalf("got %q / %q / %v", display, addr, ok)
	}
	if _, addr, ok = SplitMailbox("relay@example.at"); !ok || addr != "relay@example.at" {
		t.Fatalf("bare address rejected: %q / %v", addr, ok)
	}
}

func TestValidSenderPattern(t *testing.T) {
	for _, s := range []string{"*", "*@", "*@example", "*.at", "a@*"} {
		if ValidSenderPattern(s) {
			t.Errorf("ValidSenderPattern(%q) = true, want false", s)
		}
	}
	for _, s := range []string{"*@example.at", "erp@example.at"} {
		if !ValidSenderPattern(s) {
			t.Errorf("ValidSenderPattern(%q) = false, want true", s)
		}
	}
}

func TestDomainOf(t *testing.T) {
	if got := DomainOf("A@Example.AT"); got != "example.at" {
		t.Fatalf("got %q", got)
	}
	if got := DomainOf("nobody"); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}
