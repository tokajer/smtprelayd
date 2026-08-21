// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tokajer/smtprelayd/internal/authms365"
	"github.com/tokajer/smtprelayd/internal/spool"
)

// Registry accumulates delivery counters and reads live gauges from the
// spool and the cached OAuth tokens at scrape time. Everything here is
// in-memory only and resets on restart: Checkmk polls continuously, so no
// history is needed, and persisting counters would outlive the retry state
// they describe.
type Registry struct {
	spool  *spool.Spool
	tokens map[string]*authms365.TokenSource // route -> token source, xoauth2 routes only
	routes []string                          // sorted, for deterministic exposition
	start  time.Time

	mu                  sync.Mutex
	delivered           map[string]uint64
	bounced             map[string]uint64
	deferredCnt         map[string]uint64
	authFailures        map[string]uint64
	lastDelivery        map[string]time.Time
	apiAuthFailure      uint64
	notificationFailure uint64
}

// New builds a registry seeded with zero counters for every configured
// route, so a route that has never delivered still reports 0 instead of
// being absent from the exposition until its first event.
func New(sp *spool.Spool, routes []string, tokens map[string]*authms365.TokenSource) *Registry {
	sorted := append([]string(nil), routes...)
	sort.Strings(sorted)

	r := &Registry{
		spool:        sp,
		tokens:       tokens,
		routes:       sorted,
		start:        time.Now(),
		delivered:    map[string]uint64{},
		bounced:      map[string]uint64{},
		deferredCnt:  map[string]uint64{},
		authFailures: map[string]uint64{},
		lastDelivery: map[string]time.Time{},
	}
	for _, name := range sorted {
		r.delivered[name] = 0
		r.bounced[name] = 0
		r.deferredCnt[name] = 0
		r.authFailures[name] = 0
	}
	return r
}

// Delivered records a successful delivery on route.
func (r *Registry) Delivered(route string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.delivered[route]++
	r.lastDelivery[route] = time.Now()
}

// Bounced records a permanent failure or an expiry in queue on route.
func (r *Registry) Bounced(route string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bounced[route]++
}

// Deferred records a temporary failure that returned the message to the
// spool for retry on route.
func (r *Registry) Deferred(route string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deferredCnt[route]++
}

// AuthFailure records a delivery attempt that failed because of the relay's
// own credentials rather than the message.
func (r *Registry) AuthFailure(route string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authFailures[route]++
}

// APIAuthFailure records a rejected bearer token on the HTTP API. It has no
// source-address label deliberately: an attacker choosing that label's
// values would otherwise be able to grow the exposition without bound. The
// source address is still logged, per docs/guides/API.md; only the metric itself
// stays a single counter.
func (r *Registry) APIAuthFailure() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.apiAuthFailure++
}

// NotificationFailure records a delivery attempt for a bounce-digest
// message itself failing. It is deliberately not counted against the
// triggering route's own delivered/bounced/deferred totals: those describe
// the relay's client-facing traffic, and a notification failure would
// otherwise be indistinguishable from a real production delivery problem on
// that route.
func (r *Registry) NotificationFailure() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notificationFailure++
}

// Uptime reports how long this registry — and with it, the process — has
// been running. Used by the API's health endpoint so it does not need its
// own separate start-time bookkeeping.
func (r *Registry) Uptime() time.Duration {
	return time.Since(r.start)
}

// RouteStatus is a point-in-time snapshot of one route's counters and cached
// token. It backs both the text exposition and the web dashboard's route
// status page, so the two never disagree about what a route's state is.
type RouteStatus struct {
	Route         string
	Queued        int
	Deferred      int
	OldestQueued  time.Time // zero if Queued == 0
	Delivered     uint64
	Bounced       uint64
	DeferredTotal uint64
	AuthFailures  uint64
	LastDelivery  time.Time // zero if there has been none
	TokenAge      time.Duration
	HasToken      bool // false for a non-xoauth2 route or before its first token fetch
}

// Status returns a snapshot of every configured route, sorted by name.
func (r *Registry) Status() []RouteStatus {
	r.mu.Lock()
	delivered := cloneCounts(r.delivered)
	bounced := cloneCounts(r.bounced)
	deferredCnt := cloneCounts(r.deferredCnt)
	authFailures := cloneCounts(r.authFailures)
	lastDelivery := make(map[string]time.Time, len(r.lastDelivery))
	for k, v := range r.lastDelivery {
		lastDelivery[k] = v
	}
	r.mu.Unlock()

	var depth map[string]spool.RouteDepth
	if r.spool != nil {
		depth = r.spool.QueueDepth(time.Now())
	}

	out := make([]RouteStatus, 0, len(r.routes))
	for _, route := range r.routes {
		d := depth[route]
		st := RouteStatus{
			Route:         route,
			Queued:        d.Queued,
			Deferred:      d.Deferred,
			OldestQueued:  d.OldestQueued,
			Delivered:     delivered[route],
			Bounced:       bounced[route],
			DeferredTotal: deferredCnt[route],
			AuthFailures:  authFailures[route],
			LastDelivery:  lastDelivery[route],
		}
		if ts, ok := r.tokens[route]; ok {
			if age, ok := ts.TokenAge(); ok {
				st.TokenAge, st.HasToken = age, true
			}
		}
		out = append(out, st)
	}
	return out
}

// text renders the current state in Prometheus text exposition format.
func (r *Registry) text() string {
	status := r.Status()
	uptime := time.Since(r.start).Seconds()

	r.mu.Lock()
	apiAuthFailure := r.apiAuthFailure
	notificationFailure := r.notificationFailure
	r.mu.Unlock()

	var b strings.Builder

	b.WriteString("# HELP smtprelayd_queue_size Number of spooled messages by state and route.\n")
	b.WriteString("# TYPE smtprelayd_queue_size gauge\n")
	for _, st := range status {
		fmt.Fprintf(&b, "smtprelayd_queue_size{route=%s,state=\"queued\"} %d\n", label(st.Route), st.Queued)
		fmt.Fprintf(&b, "smtprelayd_queue_size{route=%s,state=\"deferred\"} %d\n", label(st.Route), st.Deferred)
	}

	b.WriteString("# HELP smtprelayd_delivered_total Messages successfully delivered, by route.\n")
	b.WriteString("# TYPE smtprelayd_delivered_total counter\n")
	for _, st := range status {
		fmt.Fprintf(&b, "smtprelayd_delivered_total{route=%s} %d\n", label(st.Route), st.Delivered)
	}

	b.WriteString("# HELP smtprelayd_bounced_total Messages that failed permanently or expired in queue, by route.\n")
	b.WriteString("# TYPE smtprelayd_bounced_total counter\n")
	for _, st := range status {
		fmt.Fprintf(&b, "smtprelayd_bounced_total{route=%s} %d\n", label(st.Route), st.Bounced)
	}

	b.WriteString("# HELP smtprelayd_deferred_total Delivery attempts that failed temporarily and were retried, by route.\n")
	b.WriteString("# TYPE smtprelayd_deferred_total counter\n")
	for _, st := range status {
		fmt.Fprintf(&b, "smtprelayd_deferred_total{route=%s} %d\n", label(st.Route), st.DeferredTotal)
	}

	b.WriteString("# HELP smtprelayd_auth_failures_total Delivery attempts rejected because of the relay's own credentials, by route.\n")
	b.WriteString("# TYPE smtprelayd_auth_failures_total counter\n")
	for _, st := range status {
		fmt.Fprintf(&b, "smtprelayd_auth_failures_total{route=%s} %d\n", label(st.Route), st.AuthFailures)
	}

	b.WriteString("# HELP smtprelayd_oauth_token_age_seconds Age of the cached OAuth2 access token, by route. Absent until a token has been issued.\n")
	b.WriteString("# TYPE smtprelayd_oauth_token_age_seconds gauge\n")
	for _, st := range status {
		if st.HasToken {
			fmt.Fprintf(&b, "smtprelayd_oauth_token_age_seconds{route=%s} %.0f\n", label(st.Route), st.TokenAge.Seconds())
		}
	}

	b.WriteString("# HELP smtprelayd_last_delivery_time Unix timestamp of the last successful delivery, by route. Absent until the first delivery.\n")
	b.WriteString("# TYPE smtprelayd_last_delivery_time gauge\n")
	for _, st := range status {
		if !st.LastDelivery.IsZero() {
			fmt.Fprintf(&b, "smtprelayd_last_delivery_time{route=%s} %d\n", label(st.Route), st.LastDelivery.Unix())
		}
	}

	// Approximated as the plan decided: delivered_total divided by process
	// uptime rather than a true rolling window, which is sufficient for a
	// service handling on the order of 0.1 messages per second.
	b.WriteString("# HELP smtprelayd_delivery_rate_per_minute Approximate delivery rate (delivered_total / uptime), by route.\n")
	b.WriteString("# TYPE smtprelayd_delivery_rate_per_minute gauge\n")
	for _, st := range status {
		rate := 0.0
		if uptime > 0 {
			rate = float64(st.Delivered) / uptime * 60
		}
		fmt.Fprintf(&b, "smtprelayd_delivery_rate_per_minute{route=%s} %.4f\n", label(st.Route), rate)
	}

	b.WriteString("# HELP smtprelayd_api_auth_failures_total Rejected bearer tokens on the HTTP API.\n")
	b.WriteString("# TYPE smtprelayd_api_auth_failures_total counter\n")
	fmt.Fprintf(&b, "smtprelayd_api_auth_failures_total %d\n", apiAuthFailure)

	b.WriteString("# HELP smtprelayd_notification_failures_total Bounce-digest notification messages that themselves failed to deliver.\n")
	b.WriteString("# TYPE smtprelayd_notification_failures_total counter\n")
	fmt.Fprintf(&b, "smtprelayd_notification_failures_total %d\n", notificationFailure)

	return b.String()
}

func cloneCounts(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// label formats a route name as a quoted Prometheus label value. Route names
// are already restricted to a safe identifier set by the config loader; the
// escaping here is defensive rather than load-bearing.
func label(route string) string {
	route = strings.ReplaceAll(route, `\`, `\\`)
	route = strings.ReplaceAll(route, `"`, `\"`)
	route = strings.ReplaceAll(route, "\n", `\n`)
	return `"` + route + `"`
}
