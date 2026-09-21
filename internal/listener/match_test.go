// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"net/netip"
	"testing"

	"github.com/tokajer/smtprelayd/internal/config"
)

func TestMatcherDefaultDeny(t *testing.T) {
	m, err := NewMatcher([]config.Client{{Name: "printers", CIDR: []string{"10.10.5.0/24"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"10.10.6.1", "192.0.2.1", "127.0.0.1", "::1"} {
		if c, _, ok := m.Match(netip.MustParseAddr(s)); ok {
			t.Errorf("%s matched client %q, want deny", s, c.Name)
		}
	}
	if _, _, ok := m.Match(netip.MustParseAddr("10.10.5.7")); !ok {
		t.Error("10.10.5.7 did not match its own client")
	}
}

func TestMatcherLongestPrefixWins(t *testing.T) {
	m, err := NewMatcher([]config.Client{
		{Name: "wide", CIDR: []string{"10.0.0.0/8"}},
		{Name: "narrow", CIDR: []string{"10.20.0.15/32"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, bits, ok := m.Match(netip.MustParseAddr("10.20.0.15"))
	if !ok || c.Name != "narrow" {
		t.Fatalf("got %v %v, want narrow", c, ok)
	}
	if bits != 32 {
		t.Fatalf("matched prefix length %d, want 32", bits)
	}
}

func TestMatcherIPv4MappedIsNotBypass(t *testing.T) {
	// A dual-stack listener reports ::ffff:10.10.5.7; if that failed to match
	// it would be a deny, but if an unlisted address matched it would be a
	// relay. Both directions are checked.
	m, _ := NewMatcher([]config.Client{{Name: "printers", CIDR: []string{"10.10.5.0/24"}}})
	if _, _, ok := m.Match(netip.MustParseAddr("::ffff:10.10.5.7")); !ok {
		t.Error("mapped address of an allowed client was denied")
	}
	if _, _, ok := m.Match(netip.MustParseAddr("::ffff:10.10.6.7")); ok {
		t.Error("mapped address outside the allowlist was accepted")
	}
}
