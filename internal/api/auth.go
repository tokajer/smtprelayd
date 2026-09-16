// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package api

import (
	"sync"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
)

// tokenInfo is what a successfully matched bearer token tells the caller
// about itself.
type tokenInfo struct {
	Name  string
	Scope string
}

// checkToken validates a bearer token against the configured digests. The
// constant-time comparison itself lives in config.MatchToken, which the
// metrics endpoint authenticates against too.
func checkToken(cfg *config.Config, presented string) (tokenInfo, bool) {
	t, ok := cfg.MatchToken(presented)
	if !ok {
		return tokenInfo{}, false
	}
	return tokenInfo{Name: t.Name, Scope: t.Scope}, true
}

// Rate-limit tuning for repeated authentication failures, per docs/guides/API.md:
// "5 failures per minute before exponential backoff."
const (
	failWindow        = time.Minute
	failThreshold     = 5
	baseBackoff       = 30 * time.Second
	maxBackoff        = 10 * time.Minute
	maxTrackedSources = 4096
)

type failState struct {
	windowStart  time.Time
	fails        int
	blockedUntil time.Time
}

// failLimiter tracks failed-auth backoff per source address. Entries whose
// backoff and failure window have both expired are pruned opportunistically
// so that cycling through many source addresses cannot grow this without
// bound.
type failLimiter struct {
	mu    sync.Mutex
	state map[string]*failState
}

func newFailLimiter() *failLimiter {
	return &failLimiter{state: map[string]*failState{}}
}

// blocked reports whether source is currently in backoff, and if so for how
// much longer.
func (l *failLimiter) blocked(source string, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.state[source]
	if !ok || !now.Before(st.blockedUntil) {
		return 0, false
	}
	return st.blockedUntil.Sub(now), true
}

func (l *failLimiter) recordFailure(source string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, tracked := l.state[source]; !tracked {
		l.makeRoomLocked(now)
	}
	st, ok := l.state[source]
	if !ok || now.Sub(st.windowStart) > failWindow {
		st = &failState{windowStart: now}
		l.state[source] = st
	}
	st.fails++
	if st.fails >= failThreshold {
		shift := st.fails - failThreshold
		if shift > 8 {
			shift = 8 // caps the exponent well before the shift itself could overflow
		}
		backoff := baseBackoff << shift
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		st.blockedUntil = now.Add(backoff)
	}
}

func (l *failLimiter) recordSuccess(source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.state, source)
}

// evictLocked drops entries whose backoff and failure window have both
// expired. Called with mu already held.
func (l *failLimiter) evictLocked(now time.Time) {
	for k, st := range l.state {
		if now.After(st.blockedUntil) && now.Sub(st.windowStart) > failWindow {
			delete(l.state, k)
		}
	}
}

// makeRoomLocked enforces maxTrackedSources as an actual ceiling before a new
// source is admitted. Called with mu already held.
//
// Expiry alone does not bound the table: a caller cycling addresses fast
// enough keeps every entry unexpired, so evictLocked finds nothing to drop
// and the map grows without limit -- which is exactly what the constant was
// there to prevent. When expiry frees nothing, the entry whose backoff ends
// soonest is dropped instead. An entry that was never blocked carries a zero
// blockedUntil and so is always chosen ahead of one still serving a backoff,
// because evicting a blocked source would hand it a way out of its own
// backoff. That only happens once every tracked source is blocked, which
// costs failThreshold failures on each of maxTrackedSources addresses.
func (l *failLimiter) makeRoomLocked(now time.Time) {
	if len(l.state) < maxTrackedSources {
		return
	}
	l.evictLocked(now)
	for len(l.state) >= maxTrackedSources {
		var victim string
		var soonest time.Time
		for k, st := range l.state {
			if victim == "" || st.blockedUntil.Before(soonest) {
				victim, soonest = k, st.blockedUntil
			}
		}
		if victim == "" {
			return
		}
		delete(l.state, victim)
	}
}
