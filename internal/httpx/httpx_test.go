// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package httpx

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// The loopback trust boundary. A page the operator visits can point a name it
// controls at 127.0.0.1 and then talk to an unauthenticated local endpoint
// same-origin, and the Host header is the only part of such a request that
// still carries the attacker's name. Both the dashboard's listener and a
// loopback metrics listener depend on this, and it used to be written out
// once in each of them.
func TestRequireLoopbackHost(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reached := false
	h := RequireLoopbackHost(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }), log)

	for host, want := range map[string]int{
		"127.0.0.1":                    http.StatusOK,
		"127.0.0.1:8025":               http.StatusOK,
		"localhost":                    http.StatusOK,
		"localhost:9100":               http.StatusOK,
		"[::1]":                        http.StatusOK,
		"[::1]:8025":                   http.StatusOK,
		"rebind.attacker.example":      http.StatusMisdirectedRequest,
		"rebind.attacker.example:8025": http.StatusMisdirectedRequest,
		// A name that merely starts with the loopback literal is not it.
		"127.0.0.1.attacker.example": http.StatusMisdirectedRequest,
		"metrics.internal:9100":      http.StatusMisdirectedRequest,
		"example.com":                http.StatusMisdirectedRequest,
	} {
		reached = false
		req := httptest.NewRequest(http.MethodGet, "/queue", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if want == http.StatusOK {
			if !reached {
				t.Errorf("Host %q was refused with %d", host, rec.Code)
			}
			continue
		}
		if reached {
			t.Errorf("Host %q reached the handler behind the guard", host)
		}
		if rec.Code != want {
			t.Errorf("Host %q: status %d, want %d", host, rec.Code, want)
		}
		// The remedy has to be in the body: a reverse proxy forwards the
		// original Host by default and would otherwise fail here blind.
		if !strings.Contains(rec.Body.String(), "reverse proxy") {
			t.Errorf("Host %q: the refusal does not name its remedy: %s", host, rec.Body.String())
		}
	}
}
