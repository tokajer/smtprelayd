// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package delivery

import (
	"sync"
	"time"
)

// routeLimiter paces the messages handed to one smarthost. Microsoft 365
// answers a burst with 4.7.500 rather than queueing it, and a rejected attempt
// costs a full connection and an authentication round trip, so pacing here is
// cheaper than retrying there.
type routeLimiter struct {
	mu      sync.Mutex
	buckets map[string]*routeBucket
}

type routeBucket struct {
	tokens   int
	refilled time.Time
}

func newRouteLimiter() *routeLimiter {
	return &routeLimiter{buckets: map[string]*routeBucket{}}
}

// allow consumes one token for route. A limit of zero or less means unlimited.
// When it returns false the duration is how long the caller should defer the
// message; it is never shorter than a second, so an exhausted bucket cannot
// turn the dispatcher into a spin loop.
func (r *routeLimiter) allow(route string, limit int, now time.Time) (time.Duration, bool) {
	if limit <= 0 {
		return 0, true
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	b, ok := r.buckets[route]
	if !ok || now.Sub(b.refilled) >= time.Minute {
		b = &routeBucket{tokens: limit, refilled: now}
		r.buckets[route] = b
	}
	if b.tokens <= 0 {
		wait := time.Minute - now.Sub(b.refilled)
		if wait < time.Second {
			wait = time.Second
		}
		return wait, false
	}
	b.tokens--
	return 0, true
}
