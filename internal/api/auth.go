// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package api

import (
	"net"
	"net/http"
	"strings"
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

// scopeSatisfies reports whether a token's scope permits an action that
// requires need. admin satisfies everything; read only satisfies itself.
func scopeSatisfies(have, need string) bool {
	return config.ScopeSatisfies(have, need)
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// sourceAddr strips the port from RemoteAddr for use as the rate limiter and
// audit log key. X-Forwarded-For is deliberately not consulted: trusting it
// without a documented reverse-proxy in front of this listener would let any
// client spoof another source's identity for both the limiter and the log.
func sourceAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Rate-limit tuning for repeated authentication failures, per docs/API.md:
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
	if len(l.state) > maxTrackedSources {
		l.evictLocked(now)
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
		backoff := baseBackoff * time.Duration(uint(1)<<uint(shift))
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
