// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package ratelimit is the per-minute token bucket both sides of the relay
// pace themselves with.
//
// It was written twice: internal/listener capped a compromised internal
// device, internal/delivery paced what it hands one smarthost, and the two
// were the same algorithm in two files differing only in whether the caller
// wanted a bool or also the wait. Consolidated 2026-09-21 — a correctness fix
// to a bucket refill is not something to have to remember to apply in two
// places, and internal/config's negative-value check already had to reason
// about both call sites at once.
//
// Not everything that counts per key belongs here. internal/api's failLimiter
// tracks failed authentication per source address, and its keys are chosen by
// whoever is failing to authenticate, so it needs eviction and a ceiling on
// the table. A Limiter has neither, deliberately; see the note on Limiter.
package ratelimit

import (
	"sync"
	"time"
)

// window is the refill period: a bucket is refilled in full once this much
// time has passed since it was last filled.
//
// A minute because that is what both configuration fields this serves are
// named for -- client.rate_limit_per_min and route.rate_limit_per_min -- so
// making it configurable here would let those two names lie.
const window = time.Minute

// minWait is the shortest wait Allow reports for an exhausted bucket. The
// delivery dispatcher defers a message by whatever comes back and ticks
// again, so the near-zero wait the arithmetic yields at the very end of a
// window would turn that into a spin loop.
const minWait = time.Second

// Limiter hands out at most limit tokens per key per minute. It is safe for
// concurrent use.
//
// **The key space has to be bounded by the configuration.** Nothing here ever
// drops a bucket, so a caller keying this on anything a client can choose
// would grow the map without limit. Both callers key it on a configured name
// -- a client's or a route's -- of which there are as many as the operator
// wrote down. A per-source-address limiter is a different thing and needs
// eviction; internal/api has one.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens   int
	refilled time.Time
}

// New returns an empty Limiter. Buckets are created on first use, so no key
// has to be declared up front.
func New() *Limiter {
	return &Limiter{buckets: map[string]*bucket{}}
}

// Allow consumes one token for key and reports whether the caller may
// proceed. A limit of zero or less means unlimited.
//
// The limit is a parameter and is deliberately not stored on the bucket: it
// comes from the configuration on every call and cannot change while the
// process runs, so a copy on the bucket would only be a second place for it
// to be wrong.
//
// wait is meaningful only when ok is false, where it is how long until the
// bucket refills, never less than minWait. A caller that has nothing to
// schedule can ignore it: the listener refuses the transaction outright,
// while the dispatcher defers the message by exactly this much.
func (l *Limiter) Allow(key string, limit int, now time.Time) (wait time.Duration, ok bool) {
	if limit <= 0 {
		return 0, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	b, found := l.buckets[key]
	if !found || now.Sub(b.refilled) >= window {
		b = &bucket{tokens: limit, refilled: now}
		l.buckets[key] = b
	}
	if b.tokens <= 0 {
		wait = window - now.Sub(b.refilled)
		if wait < minWait {
			wait = minWait
		}
		return wait, false
	}
	b.tokens--
	return 0, true
}
