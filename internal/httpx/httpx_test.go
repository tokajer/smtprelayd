// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package httpx

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestBearerTokenAcceptsOnlyTheBearerScheme(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"", ""},
		{"Bearer abc123", "abc123"},
		{"Bearer   abc123  ", "abc123"},
		// The scheme is case-sensitive and the space is required: anything
		// else must yield no credential rather than a partial one.
		{"bearer abc123", ""},
		{"BEARER abc123", ""},
		{"Bearerabc123", ""},
		{"Basic abc123", ""},
		{"Bearer", ""},
		{"Bearer ", ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.header != "" {
			r.Header.Set("Authorization", c.header)
		}
		if got := BearerToken(r); got != c.want {
			t.Errorf("BearerToken(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}

func TestSourceAddrStripsPortAndIgnoresForwardedFor(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.7:54321"
	// Honouring this header would let any client claim any source and so
	// evade the failed-auth backoff keyed on the result.
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	if got := SourceAddr(r); got != "192.0.2.7" {
		t.Fatalf("SourceAddr() = %q, want %q", got, "192.0.2.7")
	}

	r.RemoteAddr = "[2001:db8::1]:443"
	if got := SourceAddr(r); got != "2001:db8::1" {
		t.Fatalf("SourceAddr() = %q, want %q", got, "2001:db8::1")
	}

	// A RemoteAddr with no port is returned whole rather than discarded.
	r.RemoteAddr = "192.0.2.7"
	if got := SourceAddr(r); got != "192.0.2.7" {
		t.Fatalf("SourceAddr() = %q, want %q", got, "192.0.2.7")
	}
}

func TestParseTimeRange(t *testing.T) {
	var since, until *time.Time

	if msg := ParseTimeRange(url.Values{}, &since, &until); msg != "" {
		t.Fatalf("no parameters: got %q, want no error", msg)
	}
	if since != nil || until != nil {
		t.Fatal("absent parameters must leave both pointers untouched")
	}

	q := url.Values{"since": {"2026-01-01T00:00:00Z"}, "until": {"2026-01-02T00:00:00Z"}}
	if msg := ParseTimeRange(q, &since, &until); msg != "" {
		t.Fatalf("valid range: got %q, want no error", msg)
	}
	if since == nil || !since.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("since = %v, want 2026-01-01T00:00:00Z", since)
	}
	if until == nil || !until.Equal(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("until = %v, want 2026-01-02T00:00:00Z", until)
	}

	// A layout other than RFC 3339 is reported, never guessed at.
	var s2, u2 *time.Time
	if msg := ParseTimeRange(url.Values{"since": {"2026-01-01"}}, &s2, &u2); msg == "" {
		t.Fatal("a date-only since must be rejected")
	}
	if s2 != nil {
		t.Fatal("a rejected since must not be assigned")
	}
	if msg := ParseTimeRange(url.Values{"until": {"yesterday"}}, &s2, &u2); msg == "" {
		t.Fatal("an unparsable until must be rejected")
	}
}
