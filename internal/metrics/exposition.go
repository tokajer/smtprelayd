// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// The Prometheus text exposition: the metric families, in the order they are
// written, and the one-shot read of the Registry they render from.
//
// Split out of metrics.go on 2026-09-21. A Registry is two things -- the
// process's in-memory operational counter store, whose Status() is the read
// model the dashboard's route page and sidebar and GET /api/v1/queue all
// render from, and the source of this exposition -- and the two were one
// file, so a change to the wire format landed next to the data three HTTP
// surfaces depend on. The line drawn here is "how it is rendered" against
// "what is counted"; how it is *served* is http.go.
//
// Nothing here is exported. The exposition has one caller, Registry.ServeHTTP
// in http.go, and an exported renderer with no caller outside the package
// would be API surface for its own sake.

package metrics

import (
	"fmt"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/expiry"
)

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
