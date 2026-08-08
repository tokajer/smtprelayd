// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"net/netip"
	"sync"
	"time"

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

// rateLimiter is a per-client token bucket refilled once per minute. It caps
// a compromised internal device without needing per-message state.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens   int
	limit    int
	refilled time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: map[string]*bucket{}}
}

// allow consumes one token for name. A limit of zero or less means unlimited.
func (r *rateLimiter) allow(name string, limit int, now time.Time) bool {
	if limit <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[name]
	if !ok {
		b = &bucket{tokens: limit, limit: limit, refilled: now}
		r.buckets[name] = b
	}
	if now.Sub(b.refilled) >= time.Minute {
		b.tokens = limit
		b.limit = limit
		b.refilled = now
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

// connCounter enforces concurrent connection caps. Keys are client names for
// allowlisted sources and the remote address for unmatched ones, so a key is
// attacker-influenced and an exhausted entry must not be left behind.
type connCounter struct {
	mu sync.Mutex
	n  map[string]int
}

func newConnCounter() *connCounter { return &connCounter{n: map[string]int{}} }

func (c *connCounter) acquire(name string, limit int) bool {
	if limit <= 0 {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n[name] >= limit {
		return false
	}
	c.n[name]++
	return true
}

func (c *connCounter) release(name string, limit int) {
	if limit <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Dropping the entry at zero rather than leaving it at zero is what keeps
	// the map bounded by concurrent connections instead of by the number of
	// distinct source addresses that have ever connected.
	if c.n[name] > 1 {
		c.n[name]--
		return
	}
	delete(c.n, name)
}
