// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"net/netip"

	"github.com/tokajer/smtprelayd/internal/config"
)

// Matcher resolves a source address to a configured client. Overlapping CIDRs
// are rejected at configuration load time, so the longest prefix match here is
// unambiguous by construction.
type Matcher struct {
	entries []matchEntry
}

type matchEntry struct {
	prefix netip.Prefix
	client *config.Client
}

// NewMatcher builds the lookup table. It assumes the configuration has been
// validated.
func NewMatcher(clients []config.Client) (*Matcher, error) {
	m := &Matcher{}
	for i := range clients {
		for _, s := range clients[i].CIDR {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, err
			}
			m.entries = append(m.entries, matchEntry{prefix: p.Masked(), client: &clients[i]})
		}
	}
	return m, nil
}

// Match returns the client owning addr and the prefix length that matched.
// The prefix length is what lets a route source network compete with a client
// on specificity instead of one silently winning. A miss is a hard deny:
// there is no default-allow path anywhere in this package.
func (m *Matcher) Match(addr netip.Addr) (*config.Client, int, bool) {
	addr = addr.Unmap()
	var best *config.Client
	bits := -1
	for _, e := range m.entries {
		if e.prefix.Contains(addr) && e.prefix.Bits() > bits {
			best, bits = e.client, e.prefix.Bits()
		}
	}
	return best, bits, best != nil
}
