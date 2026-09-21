// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/expiry"
	"github.com/tokajer/smtprelayd/internal/spool"
)

// TokenAger is the whole of what this package needs from a route's OAuth2
// token source: how old the cached token is, and whether one has been
// fetched at all. It is declared here, on the consumer side, so that the
// metrics endpoint does not depend on the Microsoft 365 auth implementation
// for the sake of a single gauge -- internal/authms365 satisfies it without
// knowing this exists.
type TokenAger interface {
	TokenAge() (time.Duration, bool)
}

// ExpirySource reports the deadlines the expiry gauges describe. It is the
// whole of what the registry needs from the configuration, declared here on
// the consumer side the way TokenAger is: the registry used to hold a
// *config.Config for this one family and nothing else, so every field of the
// configuration was reachable from a counter table.
type ExpirySource func() ([]expiry.Item, error)

// ConfigExpiry is the ExpirySource the service uses: what internal/expiry
// finds in a loaded configuration. It exists so the composition root can wire
// the registry without either side growing an import for it.
func ConfigExpiry(cfg *config.Config) ExpirySource {
	return func() ([]expiry.Item, error) { return expiry.Items(cfg) }
}

// Registry accumulates delivery counters and reads live gauges from the
// spool and the cached OAuth tokens at scrape time. Everything here is
// in-memory only and resets on restart: Checkmk polls continuously, so no
// history is needed, and persisting counters would outlive the retry state
// they describe.
//
// Despite the package name it is not only the exposition's backing store.
// Status() is the read model the dashboard's route page and sidebar and the
// JSON API's /queue endpoint all render from, which is why those two import
// this package.
//
// **A nil *Registry is for tests, not for a running service.** The listener,
// the dashboard and the API each guard their uses with a nil check, and
// several of their doc comments used to describe the result as what happens
// "if metrics are disabled". That was never reachable: cmd/smtprelayd builds
// a registry unconditionally and hands the same one to everything, because
// the listener's session-panic and journal-failure counters and the
// dashboard's route page need it whether or not a metrics listener is bound.
// metrics.enabled governs the HTTP endpoint alone. The nil case exists so a
// test can construct a listener or a server without caring about counters.
type Registry struct {
	// expiry is read at scrape time for the expiry gauges; see ExpirySource.
	expiry      ExpirySource
	spool       *spool.Spool
	routes      []string // sorted, for deterministic exposition
	canaryNames []string // sorted, for deterministic exposition
	start       time.Time

	mu                  sync.Mutex
	tokens              map[string]TokenAger // route -> token source, xoauth2 routes only
	delivered           map[string]uint64
	bounced             map[string]uint64
	deferredCnt         map[string]uint64
	authFailures        map[string]uint64
	recipientsRefused   map[string]uint64
	lastDelivery        map[string]time.Time
	apiAuthFailure      uint64
	notificationFailure uint64
	canaryFailure       map[string]uint64
	lastCanaryDelivery  map[string]time.Time
	sessionPanics       uint64
	journalWriteFails   uint64
}

// New builds a registry seeded with zero counters for every configured
// route and every configured canary, so one that has never delivered still
// reports 0 instead of being absent from the exposition until its first
// event. tokens may be nil; the delivery manager registers its token sources
// through RegisterTokenAger once it has built them, which is what lets the
// registry exist before the manager and be handed to the listener. exp may be
// nil too, in which case the exposition simply omits the expiry families --
// which is what a caller with no deadlines to report wants, and what a
// configuration naming neither a certificate nor an xoauth2 route produced
// anyway.
func New(exp ExpirySource, sp *spool.Spool, routes, canaryNames []string, tokens map[string]TokenAger) *Registry {
	sorted := append([]string(nil), routes...)
	sort.Strings(sorted)
	sortedCanaries := append([]string(nil), canaryNames...)
	sort.Strings(sortedCanaries)

	r := &Registry{
		expiry:             exp,
		spool:              sp,
		tokens:             map[string]TokenAger{},
		routes:             sorted,
		canaryNames:        sortedCanaries,
		start:              time.Now(),
		delivered:          map[string]uint64{},
		bounced:            map[string]uint64{},
		deferredCnt:        map[string]uint64{},
		authFailures:       map[string]uint64{},
		recipientsRefused:  map[string]uint64{},
		lastDelivery:       map[string]time.Time{},
		canaryFailure:      map[string]uint64{},
		lastCanaryDelivery: map[string]time.Time{},
	}
	for _, name := range sorted {
		r.delivered[name] = 0
		r.bounced[name] = 0
		r.deferredCnt[name] = 0
		r.authFailures[name] = 0
		r.recipientsRefused[name] = 0
	}
	for _, name := range sortedCanaries {
		r.canaryFailure[name] = 0
	}
	for route, t := range tokens {
		r.tokens[route] = t
	}
	return r
}

// RegisterTokenAger attaches the token source whose age the route's gauge
// reports. Called by the delivery manager for each xoauth2 route it builds.
func (r *Registry) RegisterTokenAger(route string, t TokenAger) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens[route] = t
}

// SessionPanic records a listener session that ended in a recovered panic.
// docs/dev/EXPLOIT-SURFACE.md section 6 asks for exactly this: a recover that
// only logs hides a parser bug that an attacker can trigger at will, and a
// counter is what a monitoring system can alert on.
func (r *Registry) SessionPanic() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessionPanics++
}

// JournalWriteFailure records a history-store write the listener or the
// delivery manager could not complete. Those writes are best-effort by
// design -- the message is queued or delivered regardless -- which is
// precisely why a broken database has to be visible somewhere other than an
// empty dashboard.
func (r *Registry) JournalWriteFailure() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.journalWriteFails++
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

// RecipientsRefused records recipients a smarthost refused permanently while
// accepting the message for the others on the same queue entry.
//
// It exists because that outcome is otherwise invisible to monitoring. The
// message is delivered, so it increments delivered_total and nothing else --
// but before partial delivery existed the same dead address bounced the whole
// message, which showed up in bounced_total and in the bounce digest. Fixing
// the mail loss removed the only signal an operator had, and /metrics is what
// docs/guides/API.md points monitoring at. This is that signal.
func (r *Registry) RecipientsRefused(route string, n int) {
	if n <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recipientsRefused[route] += uint64(n) //#nosec G115 -- n is a slice length, checked positive above
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

// CanaryDelivered records one canary's own successful delivery, and when it
// happened. This, not a counter, is the signal worth alerting on: a
// monitoring system watching for the timestamp going stale catches a route
// that has silently stopped delivering even though its canary keeps being
// queued. name is the canary's own name (spool.Envelope.Client on the
// message that was delivered), not the route it happened to test — the two
// can differ if more than one canary shares a route.
func (r *Registry) CanaryDelivered(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastCanaryDelivery[name] = time.Now()
}

// CanaryFailure records one canary's own delivery attempt failing, whether
// permanently, by expiry, or deferred for retry. Kept out of the triggering
// route's own delivered/bounced/deferred/auth-failure counters for the same
// reason NotificationFailure is: a canary is diagnostic traffic, not client
// traffic, and folding it into route metrics would make them noisier
// without adding anything this dedicated counter does not already say more
// precisely.
func (r *Registry) CanaryFailure(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.canaryFailure[name]++
}

// JournalWriteFailures reports how many history-store writes have failed
// since start. The dashboard reads it to say so on the page: a message whose
// journal row was never written is in the spool and in no listing, and the
// queue view is built from the store, so without this the gap is visible
// only in the log and in /metrics.
func (r *Registry) JournalWriteFailures() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.journalWriteFails
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
	// RecipientsRefused counts recipients refused permanently on messages
	// that were delivered to the rest of their queue entry.
	RecipientsRefused uint64
	LastDelivery      time.Time // zero if there has been none
	TokenAge          time.Duration
	HasToken          bool // false for a non-xoauth2 route or before its first token fetch
}

// Status returns a snapshot of every configured route, sorted by name.
func (r *Registry) Status() []RouteStatus {
	r.mu.Lock()
	delivered := cloneCounts(r.delivered)
	bounced := cloneCounts(r.bounced)
	deferredCnt := cloneCounts(r.deferredCnt)
	authFailures := cloneCounts(r.authFailures)
	recipientsRefused := cloneCounts(r.recipientsRefused)
	lastDelivery := make(map[string]time.Time, len(r.lastDelivery))
	for k, v := range r.lastDelivery {
		lastDelivery[k] = v
	}
	tokens := make(map[string]TokenAger, len(r.tokens))
	for k, v := range r.tokens {
		tokens[k] = v
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
			Route:             route,
			Queued:            d.Queued,
			Deferred:          d.Deferred,
			OldestQueued:      d.OldestQueued,
			Delivered:         delivered[route],
			Bounced:           bounced[route],
			DeferredTotal:     deferredCnt[route],
			AuthFailures:      authFailures[route],
			RecipientsRefused: recipientsRefused[route],
			LastDelivery:      lastDelivery[route],
		}
		if ts, ok := tokens[route]; ok {
			if age, ok := ts.TokenAge(); ok {
				st.TokenAge, st.HasToken = age, true
			}
		}
		out = append(out, st)
	}
	return out
}

// snapshot is everything one scrape renders from, read once so that no two
// families in the same exposition can disagree about the state.
type snapshot struct {
	status             []RouteStatus
	uptime             float64
	canaryNames        []string
	canaryFailure      map[string]uint64
	lastCanaryDelivery map[string]time.Time
	apiAuthFailures    uint64
	notificationFails  uint64
	sessionPanics      uint64
	journalWriteFails  uint64
	expiryItems        []expiry.Item
	expiryErr          error
}

// series is one metric family: its identity, and the samples it contributes.
// The exposition is a table of these rather than a run of Fprintf calls
// because a family used to need its name, help text, type line and format
// string written out four times in one block, and adding one meant
// remembering all four plus a row in docs/guides/CHECKMK.md.
type series struct {
	name string
	kind string // counter or gauge
	help string

	// when gates the whole family, header included. Only the two expiry
	// families use it: a gauge that is present and zero says something
	// different from one that is absent, and CHECKMK.md documents which of
	// the two appears when.
	when func(*snapshot) bool

	// Exactly one of value and rows is set. value is the shorthand for a
	// family that is a single unlabelled sample, which is most of the
	// process-wide counters.
	value func(*snapshot) uint64
	rows  func(*strings.Builder, *snapshot)
}

// perRoute renders one sample per configured route, in the registry's sorted
// order, from a value the caller picks out of the route's status.
func perRoute(format string, value func(RouteStatus) any) func(*strings.Builder, *snapshot) {
	return func(b *strings.Builder, s *snapshot) {
		for _, st := range s.status {
			v := value(st)
			if v == nil {
				// Absent rather than zero: a route that has never delivered
				// has no timestamp and no token age, and reporting either as
				// zero would read as 1970 or as a token fetched just now.
				continue
			}
			fmt.Fprintf(b, format+"\n", label(st.Route), v)
		}
	}
}

// expositionSeries is the exposition, in the order it is written. Adding a
// metric is one entry here and one row in docs/guides/CHECKMK.md.
var expositionSeries = []series{
	{
		name: "smtprelayd_queue_size", kind: "gauge",
		help: "Number of spooled messages by state and route.",
		rows: func(b *strings.Builder, s *snapshot) {
			for _, st := range s.status {
				fmt.Fprintf(b, "smtprelayd_queue_size{route=%s,state=\"queued\"} %d\n", label(st.Route), st.Queued)
				fmt.Fprintf(b, "smtprelayd_queue_size{route=%s,state=\"deferred\"} %d\n", label(st.Route), st.Deferred)
			}
		},
	},
	{
		name: "smtprelayd_delivered_total", kind: "counter",
		help: "Messages successfully delivered, by route.",
		rows: perRoute("smtprelayd_delivered_total{route=%s} %d", func(st RouteStatus) any { return st.Delivered }),
	},
	{
		name: "smtprelayd_bounced_total", kind: "counter",
		help: "Messages that failed permanently or expired in queue, by route.",
		rows: perRoute("smtprelayd_bounced_total{route=%s} %d", func(st RouteStatus) any { return st.Bounced }),
	},
	{
		name: "smtprelayd_deferred_total", kind: "counter",
		help: "Delivery attempts that failed temporarily and were retried, by route.",
		rows: perRoute("smtprelayd_deferred_total{route=%s} %d", func(st RouteStatus) any { return st.DeferredTotal }),
	},
	{
		name: "smtprelayd_recipients_refused_total", kind: "counter",
		help: "Recipients a smarthost refused permanently on a message delivered to the others, by route.",
		rows: perRoute("smtprelayd_recipients_refused_total{route=%s} %d", func(st RouteStatus) any { return st.RecipientsRefused }),
	},
	{
		// Seconds rather than a date: a scrape consumer alerts on
		// "< 30*86400", which is one expression, where a date needs parsing
		// and clock arithmetic in the monitoring system. Negative once it
		// has lapsed, which is what makes "already expired" alertable with
		// the same expression rather than a second one.
		name: "smtprelayd_expiry_seconds", kind: "gauge",
		help: "Seconds until a certificate or credential expires; negative once it has.",
		when: func(s *snapshot) bool { return s.expiryErr == nil },
		rows: func(b *strings.Builder, s *snapshot) {
			for _, it := range s.expiryItems {
				fmt.Fprintf(b, "smtprelayd_expiry_seconds{item=%s} %d\n",
					label(it.Key), int64(time.Until(it.Expires).Seconds()))
			}
		},
	},
	{
		// A certificate that cannot be read is not silently absent from the
		// exposition: a gauge that vanishes looks the same as a monitoring
		// system that stopped scraping.
		name: "smtprelayd_expiry_read_errors", kind: "gauge",
		help: "Certificate or credential deadlines that could not be read.",
		when: func(s *snapshot) bool { return s.expiryErr != nil },
		rows: func(b *strings.Builder, _ *snapshot) {
			b.WriteString("smtprelayd_expiry_read_errors 1\n")
		},
	},
	{
		name: "smtprelayd_auth_failures_total", kind: "counter",
		help: "Delivery attempts rejected because of the relay's own credentials, by route.",
		rows: perRoute("smtprelayd_auth_failures_total{route=%s} %d", func(st RouteStatus) any { return st.AuthFailures }),
	},
	{
		name: "smtprelayd_oauth_token_age_seconds", kind: "gauge",
		help: "Age of the cached OAuth2 access token, by route. Absent until a token has been issued.",
		rows: perRoute("smtprelayd_oauth_token_age_seconds{route=%s} %.0f", func(st RouteStatus) any {
			if !st.HasToken {
				return nil
			}
			return st.TokenAge.Seconds()
		}),
	},
	{
		name: "smtprelayd_last_delivery_time", kind: "gauge",
		help: "Unix timestamp of the last successful delivery, by route. Absent until the first delivery.",
		rows: perRoute("smtprelayd_last_delivery_time{route=%s} %d", func(st RouteStatus) any {
			if st.LastDelivery.IsZero() {
				return nil
			}
			return st.LastDelivery.Unix()
		}),
	},
	{
		// Approximated as the plan decided: delivered_total divided by
		// process uptime rather than a true rolling window, which is
		// sufficient for a service handling on the order of 0.1 messages per
		// second.
		name: "smtprelayd_delivery_rate_per_minute", kind: "gauge",
		help: "Approximate delivery rate (delivered_total / uptime), by route.",
		rows: func(b *strings.Builder, s *snapshot) {
			for _, st := range s.status {
				rate := 0.0
				if s.uptime > 0 {
					rate = float64(st.Delivered) / s.uptime * 60
				}
				fmt.Fprintf(b, "smtprelayd_delivery_rate_per_minute{route=%s} %.4f\n", label(st.Route), rate)
			}
		},
	},
	{
		name: "smtprelayd_api_auth_failures_total", kind: "counter",
		help:  "Rejected bearer tokens on the HTTP API.",
		value: func(s *snapshot) uint64 { return s.apiAuthFailures },
	},
	{
		name: "smtprelayd_notification_failures_total", kind: "counter",
		help:  "Bounce-digest notification messages that themselves failed to deliver.",
		value: func(s *snapshot) uint64 { return s.notificationFails },
	},
	{
		name: "smtprelayd_session_panics_total", kind: "counter",
		help:  "Inbound SMTP sessions that ended in a recovered panic.",
		value: func(s *snapshot) uint64 { return s.sessionPanics },
	},
	{
		name: "smtprelayd_journal_write_failures_total", kind: "counter",
		help:  "History-store writes that failed; the message was still queued or delivered.",
		value: func(s *snapshot) uint64 { return s.journalWriteFails },
	},
	{
		name: "smtprelayd_canary_failures_total", kind: "counter",
		help: "Canary probe delivery attempts that failed, permanently, by expiry, or deferred for retry, by canary name.",
		rows: func(b *strings.Builder, s *snapshot) {
			for _, name := range s.canaryNames {
				fmt.Fprintf(b, "smtprelayd_canary_failures_total{name=%s} %d\n", label(name), s.canaryFailure[name])
			}
		},
	},
	{
		name: "smtprelayd_canary_last_delivery_time", kind: "gauge",
		help: "Unix timestamp of the last successful delivery, by canary name. Absent until that canary's first successful delivery.",
		rows: func(b *strings.Builder, s *snapshot) {
			for _, name := range s.canaryNames {
				if ts, ok := s.lastCanaryDelivery[name]; ok && !ts.IsZero() {
					fmt.Fprintf(b, "smtprelayd_canary_last_delivery_time{name=%s} %d\n", label(name), ts.Unix())
				}
			}
		},
	},
}

// snapshot reads every counter and gauge one scrape needs, once.
func (r *Registry) snapshot() *snapshot {
	s := &snapshot{
		status: r.Status(),
		uptime: time.Since(r.start).Seconds(),
	}
	if r.expiry != nil {
		s.expiryItems, s.expiryErr = r.expiry()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	s.canaryNames = r.canaryNames
	s.canaryFailure = cloneCounts(r.canaryFailure)
	s.lastCanaryDelivery = make(map[string]time.Time, len(r.lastCanaryDelivery))
	for k, v := range r.lastCanaryDelivery {
		s.lastCanaryDelivery[k] = v
	}
	s.apiAuthFailures = r.apiAuthFailure
	s.notificationFails = r.notificationFailure
	s.sessionPanics = r.sessionPanics
	s.journalWriteFails = r.journalWriteFails
	return s
}

// text renders the current state in Prometheus text exposition format.
func (r *Registry) text() string {
	snap := r.snapshot()
	var b strings.Builder
	for _, se := range expositionSeries {
		if se.when != nil && !se.when(snap) {
			continue
		}
		fmt.Fprintf(&b, "# HELP %s %s\n", se.name, se.help)
		fmt.Fprintf(&b, "# TYPE %s %s\n", se.name, se.kind)
		switch {
		case se.value != nil:
			fmt.Fprintf(&b, "%s %d\n", se.name, se.value(snap))
		case se.rows != nil:
			se.rows(&b, snap)
		}
	}
	return b.String()
}

func cloneCounts(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// label formats a route name as a quoted Prometheus label value.
//
// config.ValidName already refuses a quote, a backslash or any control
// character in a route name, so this cannot currently be reached with
// anything to escape. It stays because a Registry can be built from route
// names that did not come through the loader -- a test, or a future caller --
// and because the cost of being wrong here is a malformed exposition that a
// scraper silently misreads. Until 2026-09-17 the comment here claimed the
// loader guaranteed a safe character set when it checked only for empty and
// duplicate names, which made this the only thing standing between a
// hand-written configuration and a broken exposition.
func label(route string) string {
	route = strings.ReplaceAll(route, `\`, `\\`)
	route = strings.ReplaceAll(route, `"`, `\"`)
	route = strings.ReplaceAll(route, "\n", `\n`)
	return `"` + route + `"`
}
