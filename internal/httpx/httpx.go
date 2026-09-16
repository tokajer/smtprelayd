// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package httpx holds the request-parsing primitives the dashboard, the JSON
// API and the metrics endpoint all need.
//
// They live here rather than in each of those packages because two of them
// are security controls: BearerToken parses a credential, and SourceAddr
// decides what a rate limiter counts and what the audit log blames. Three
// copies of a control are three places to fix it and two places to forget.
package httpx

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
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
