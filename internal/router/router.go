// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package router maps recipients onto delivery routes.
//
// Precedence, decided 2026-08-08:
//
//  1. an exact recipient domain listed in route.domains
//  2. the source network: route.sources competes with the client's own
//     matched CIDR and the longer prefix wins, so a site-wide route and a
//     per-device override can coexist without duplicating route = in every
//     client
//  3. the route named by the matched client
//  4. the route marked default
//
// Recipients of one message may resolve to different routes. They are split
// into one queue entry per route rather than rejected, because a legacy
// device given a 5xx for a mixed recipient list has no way to recover.
package router

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/tokajer/smtprelayd/internal/config"
)

// Router resolves routes. It is immutable after New and safe for concurrent
// use.
type Router struct {
	byDomain map[string]string
	sources  []source
	def      string
}

type source struct {
	prefix netip.Prefix
	route  string
}

// Decision records the chosen route and why it was chosen. The reason is
// logged so that an operator can tell a domain rule from a network rule
// without re-deriving the precedence by hand.
type Decision struct {
	Route  string
	Reason string
}

// Group is a set of recipients of one message that share a route.
type Group struct {
	Route      string
	Reason     string
	Recipients []string
}

// New builds the lookup tables. Conflicts are errors: the loader reports them
// with configuration context, and this is the second line of defence for
// callers that build a Router from something else.
func New(routes []config.Route) (*Router, error) {
	r := &Router{byDomain: make(map[string]string)}
	for _, rt := range routes {
		for _, d := range rt.Domains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			if owner, dup := r.byDomain[d]; dup {
				return nil, fmt.Errorf("router: domain %q is routed by both %q and %q", d, owner, rt.Name)
			}
			r.byDomain[d] = rt.Name
		}
		for _, s := range rt.Sources {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("router: route %q: source %q: %w", rt.Name, s, err)
			}
			p = p.Masked()
			for _, o := range r.sources {
				if o.prefix.Overlaps(p) && o.route != rt.Name {
					return nil, fmt.Errorf("router: source %s of route %q overlaps %s of route %q",
						p, rt.Name, o.prefix, o.route)
				}
			}
			r.sources = append(r.sources, source{prefix: p, route: rt.Name})
		}
		if rt.Default {
			if r.def != "" {
				return nil, fmt.Errorf("router: %q and %q are both marked default", r.def, rt.Name)
			}
			r.def = rt.Name
		}
	}
	return r, nil
}

// Resolve picks the route for one recipient. clientRoute is the route named
// by the matched client and may be empty; clientBits is the prefix length of
// the client CIDR that matched, or -1 when no client matched.
func (r *Router) Resolve(rcpt string, src netip.Addr, clientRoute string, clientBits int) (Decision, bool) {
	if d := domainOf(rcpt); d != "" {
		if name, ok := r.byDomain[d]; ok {
			return Decision{Route: name, Reason: "domain"}, true
		}
	}
	if name, bits, ok := r.matchSource(src.Unmap()); ok && (clientRoute == "" || bits > clientBits) {
		return Decision{Route: name, Reason: "source"}, true
	}
	if clientRoute != "" {
		return Decision{Route: clientRoute, Reason: "client"}, true
	}
	if r.def != "" {
		return Decision{Route: r.def, Reason: "default"}, true
	}
	return Decision{}, false
}

// Split groups recipients by route, preserving the order in which they were
// accepted. An unroutable recipient is an error for the whole message: it
// means no default route exists, which is a configuration fault and not
// something to blame on one address.
func (r *Router) Split(rcpts []string, src netip.Addr, clientRoute string, clientBits int) ([]Group, error) {
	var groups []Group
	at := make(map[string]int, 2)
	for _, rcpt := range rcpts {
		d, ok := r.Resolve(rcpt, src, clientRoute, clientBits)
		if !ok {
			return nil, fmt.Errorf("router: no route for recipient domain %q", domainOf(rcpt))
		}
		i, seen := at[d.Route]
		if !seen {
			groups = append(groups, Group{Route: d.Route, Reason: d.Reason})
			i = len(groups) - 1
			at[d.Route] = i
		}
		groups[i].Recipients = append(groups[i].Recipients, rcpt)
	}
	return groups, nil
}

func (r *Router) matchSource(addr netip.Addr) (route string, bits int, ok bool) {
	bits = -1
	for _, s := range r.sources {
		if s.prefix.Contains(addr) && s.prefix.Bits() > bits {
			route, bits, ok = s.route, s.prefix.Bits(), true
		}
	}
	return route, bits, ok
}

func domainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}
