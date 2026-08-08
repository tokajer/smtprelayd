// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package router

import (
	"net/netip"
	"testing"

	"github.com/tokajer/smtprelayd/internal/config"
)

// testRoutes models the shape the precedence rules exist for: a default
// smarthost, a route claiming a recipient domain, and a route claiming a
// network more specific than the client CIDR that covers it.
func testRoutes() []config.Route {
	return []config.Route{
		{Name: "m365", Default: true},
		{Name: "partner", Domains: []string{"partner.example"}},
		{Name: "onprem", Sources: []string{"10.10.5.128/25"}},
	}
}

func mustRouter(t *testing.T, rs []config.Route) *Router {
	t.Helper()
	r, err := New(rs)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func resolve(t *testing.T, r *Router, rcpt, src, clientRoute string, clientBits int) Decision {
	t.Helper()
	d, ok := r.Resolve(rcpt, netip.MustParseAddr(src), clientRoute, clientBits)
	if !ok {
		t.Fatalf("no route for %q from %s", rcpt, src)
	}
	return d
}

func TestDomainBeatsEverything(t *testing.T) {
	r := mustRouter(t, testRoutes())
	// The source is inside the onprem network and the client names m365;
	// the recipient domain still wins.
	d := resolve(t, r, "a@partner.example", "10.10.5.200", "m365", 24)
	if d.Route != "partner" || d.Reason != "domain" {
		t.Fatalf("got %+v, want partner/domain", d)
	}
}

func TestDomainMatchIsCaseInsensitive(t *testing.T) {
	r := mustRouter(t, testRoutes())
	d := resolve(t, r, "A@PARTNER.EXAMPLE", "10.99.0.1", "m365", 24)
	if d.Route != "partner" {
		t.Fatalf("got %+v, want partner", d)
	}
}

func TestSourceBeatsClientWhenMoreSpecific(t *testing.T) {
	r := mustRouter(t, testRoutes())
	d := resolve(t, r, "a@example.at", "10.10.5.200", "m365", 24)
	if d.Route != "onprem" || d.Reason != "source" {
		t.Fatalf("got %+v, want onprem/source", d)
	}
}

func TestClientBeatsEquallySpecificSource(t *testing.T) {
	r := mustRouter(t, testRoutes())
	// A /32 client entry is more specific than the route's /25, so the
	// per-device configuration is not overridden by the site-wide rule.
	d := resolve(t, r, "a@example.at", "10.10.5.200", "m365", 32)
	if d.Route != "m365" || d.Reason != "client" {
		t.Fatalf("got %+v, want m365/client", d)
	}
}

func TestSourceUsedWhenClientNamesNoRoute(t *testing.T) {
	r := mustRouter(t, testRoutes())
	d := resolve(t, r, "a@example.at", "10.10.5.200", "", 24)
	if d.Route != "onprem" || d.Reason != "source" {
		t.Fatalf("got %+v, want onprem/source", d)
	}
}

func TestMappedIPv6SourceMatches(t *testing.T) {
	r := mustRouter(t, testRoutes())
	d := resolve(t, r, "a@example.at", "::ffff:10.10.5.200", "", -1)
	if d.Route != "onprem" {
		t.Fatalf("got %+v, want onprem", d)
	}
}

func TestDefaultIsLastResort(t *testing.T) {
	r := mustRouter(t, testRoutes())
	d := resolve(t, r, "a@example.at", "10.99.0.1", "", -1)
	if d.Route != "m365" || d.Reason != "default" {
		t.Fatalf("got %+v, want m365/default", d)
	}
}

func TestUnroutableWithoutDefault(t *testing.T) {
	r := mustRouter(t, []config.Route{{Name: "partner", Domains: []string{"partner.example"}}})
	if _, ok := r.Resolve("a@example.at", netip.MustParseAddr("10.99.0.1"), "", -1); ok {
		t.Fatal("a recipient was routed although no rule and no default matched")
	}
	if _, err := r.Split([]string{"a@example.at"}, netip.MustParseAddr("10.99.0.1"), "", -1); err == nil {
		t.Fatal("Split accepted an unroutable recipient")
	}
}

func TestSplitGroupsInAcceptanceOrder(t *testing.T) {
	r := mustRouter(t, testRoutes())
	groups, err := r.Split(
		[]string{"a@partner.example", "b@example.at", "c@partner.example"},
		netip.MustParseAddr("10.99.0.1"), "m365", 24)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}
	if groups[0].Route != "partner" || len(groups[0].Recipients) != 2 {
		t.Fatalf("first group is %+v", groups[0])
	}
	if groups[0].Recipients[1] != "c@partner.example" {
		t.Fatalf("recipient order not preserved: %+v", groups[0].Recipients)
	}
	if groups[1].Route != "m365" || len(groups[1].Recipients) != 1 {
		t.Fatalf("second group is %+v", groups[1])
	}
}

func TestDuplicateDomainIsRefused(t *testing.T) {
	_, err := New([]config.Route{
		{Name: "a", Domains: []string{"example.at"}},
		{Name: "b", Domains: []string{"example.at"}},
	})
	if err == nil {
		t.Fatal("a domain claimed by two routes was accepted")
	}
}

func TestOverlappingSourcesAreRefused(t *testing.T) {
	_, err := New([]config.Route{
		{Name: "a", Sources: []string{"10.0.0.0/8"}},
		{Name: "b", Sources: []string{"10.10.5.0/24"}},
	})
	if err == nil {
		t.Fatal("overlapping source networks of two routes were accepted")
	}
}

func TestTwoDefaultsAreRefused(t *testing.T) {
	_, err := New([]config.Route{{Name: "a", Default: true}, {Name: "b", Default: true}})
	if err == nil {
		t.Fatal("two default routes were accepted")
	}
}

func TestMalformedSourceIsRefused(t *testing.T) {
	if _, err := New([]config.Route{{Name: "a", Sources: []string{"10.0.0.0"}}}); err == nil {
		t.Fatal("a source without a prefix length was accepted")
	}
}
