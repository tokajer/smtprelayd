// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import "sync"

// Admission: how many connections one source may hold at once.
//
// Split out of match.go on 2026-09-21, which was named for the CIDR Matcher
// and also held this and the per-client rate limiter, so nothing pointed a
// reader looking for "where is the connection cap enforced" at it. The rate
// limiter went to internal/ratelimit the same day, because internal/delivery
// had the same algorithm for pacing a smarthost.

// connCounter enforces concurrent connection caps. Keys are built by
// connKeyClient and connKeyUnmatched below, so a key is attacker-influenced
// and an exhausted entry must not be left behind.
type connCounter struct {
	mu sync.Mutex
	n  map[string]int
}

// connCounter holds two key spaces, and a prefix on each is what keeps them
// apart. Without one, a client named "unmatched:10.0.0.5" -- which
// config.ValidName permits, since it is printable ASCII with no quote or
// backslash -- would share its connection budget with the unmatched source at
// that address, a budget of two. config.reservedNames refuses exactly this
// kind of collision in the bounce-grouping key space; this one had no such
// defence, and a prefix on both sides is cheaper than a second reserved-name
// list.

// connKeyClient is the counter key for an allowlisted client's connections.
func connKeyClient(name string) string { return "client:" + name }

// connKeyUnmatched is the counter key for an unauthorised source's
// connections, which is its remote address.
func connKeyUnmatched(addr string) string { return "unmatched:" + addr }

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
