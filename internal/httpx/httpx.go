// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package httpx holds the request-parsing primitives the dashboard, the JSON
// API and the metrics endpoint all need.
//
// They live here rather than in each of those packages because three of them
// are security controls: BearerToken parses a credential, SourceAddr decides
// what a rate limiter counts and what the audit log blames, and
// RequireLoopbackHost is what completes the loopback trust boundary. Three
// copies of a control are three places to fix it and two places to forget --
// which is not hypothetical: RequireLoopbackHost was written out once in
// internal/web and once in internal/metrics, the two copies had drifted to
// different log fields and different remedies in their refusal text, and
// because the dashboard's copy was applied inside its own handler rather
// than to the listener, the JSON API mounted beside it on the same socket
// was never covered at all.
package httpx

import (
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
)

// BearerToken returns the credential from an Authorization header, or "" when
// the header is absent or is not a bearer scheme. The value is returned
// verbatim for the caller to compare in constant time; nothing here decides
// whether it is valid.
func BearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// SourceAddr strips the port from RemoteAddr for use as a rate-limiter key
// and an audit log field.
//
// X-Forwarded-For is deliberately not consulted. Without a documented reverse
// proxy in front of these listeners, honouring it would let any client claim
// any source and so evade the failed-auth backoff or pin its requests on
// another address in the audit trail.
func SourceAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RequireLoopbackHost refuses a request whose Host header names anything but
// the local machine, answering 421 Misdirected Request.
//
// A loopback bind is not by itself the trust boundary for an endpoint with no
// authentication: a browser sits inside that boundary and resolves names on
// someone else's behalf, so a page the operator visits can point a name it
// controls at 127.0.0.1 and then talk to the endpoint same-origin -- DNS
// rebinding. The bind address is the server's own; the Host header is the
// client's claim, and only a request that addressed loopback by name or
// literal is served, which a rebound name cannot do.
//
// Apply it to the listener, not to one handler mounted on it. That is the
// mistake this consolidates: the dashboard wrapped its own handler, so
// /api/v1/ mounted beside it on the same socket inherited nothing -- and
// while every other API endpoint wants a bearer token a rebound page cannot
// obtain, GET /api/v1/health deliberately wants none, and it reports the
// version, the uptime, every route name and whether each route holds a valid
// token.
//
// The refusal names its own remedy rather than returning a bare 404, because
// the deployment config.Validate points operators at -- a reverse proxy that
// authenticates -- forwards the original Host by default and would otherwise
// fail here with nothing to go on. log should already carry the component it
// is guarding, since that is the only thing the two call sites differ in.
func RequireLoopbackHost(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !config.IsLoopbackHostHeader(r.Host) {
			log.Warn("request with a non-loopback Host header rejected",
				"host", r.Host, "source", SourceAddr(r), "path", r.URL.Path)
			http.Error(w, "this endpoint only answers requests addressed to loopback; "+
				"a reverse proxy in front of it must set the Host header to the "+
				"configured address", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ParseTimeRange reads the since and until query parameters into the pointers
// the caller passes, leaving a pointer untouched when its parameter is
// absent. It returns a message describing the first malformed value, or "" if
// both parsed, so the caller can render it as a form error or a JSON error as
// suits its own surface.
func ParseTimeRange(q url.Values, since, until **time.Time) string {
	if v := strings.TrimSpace(q.Get("since")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return "since must be RFC 3339, e.g. 2026-01-01T00:00:00Z"
		}
		*since = &t
	}
	if v := strings.TrimSpace(q.Get("until")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return "until must be RFC 3339, e.g. 2026-01-01T00:00:00Z"
		}
		*until = &t
	}
	return ""
}
