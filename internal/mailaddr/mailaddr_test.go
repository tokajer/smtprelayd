// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package mailaddr

import (
	"errors"
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

// json.Marshal in the spool rewrites every invalid UTF-8 octet as U+FFFD, so
// an address carrying one was relayed to a different address after a
// restart; an angle bracket inside the path is one the listener's parser
// stopped short of. Both used to pass.
func TestCheckEnvelopeRefusesWhatTheSpoolOrTheParserWouldChange(t *testing.T) {
	for _, tc := range []struct{ addr, detail string }{
		{"m\xfcller@example.at", "not valid UTF-8"},
		{"ops@example.\xff", "not valid UTF-8"},
		{"<a@b.example", "angle bracket"},
		{"a<b@c.example", "angle bracket"},
		{"a>b@c.example", "angle bracket"},
	} {
		err := CheckEnvelope(tc.addr)
		if !errors.Is(err, ErrEnvelope) {
			t.Errorf("CheckEnvelope(%q) = %v, want ErrEnvelope", tc.addr, err)
			continue
		}
		if !strings.Contains(err.Error(), tc.detail) {
			t.Errorf("CheckEnvelope(%q) = %v, want the detail %q", tc.addr, err, tc.detail)
		}
	}
	// Valid UTF-8 is still carried as is: a device may name a recipient with
	// an umlaut, and the smarthost decides whether it accepts SMTPUTF8.
	for _, addr := range []string{"jörg@example.at", "\"quoted local\"@example.at"} {
		if err := CheckEnvelope(addr); err != nil {
			t.Errorf("CheckEnvelope(%q) = %v, want nil", addr, err)
		}
	}
}
