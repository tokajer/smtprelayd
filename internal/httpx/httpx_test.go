// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package httpx

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
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

// Serve holds the shutdown path both HTTP listeners depend on, and neither of
// their own tests reaches its error branch: a listener that fails to accept
// for a reason other than being shut down has to be reported, and one that was
// shut down must not be. Both are one line apart in the same select.
func TestServeDrainsOnCancellationAndReportsRealFailures(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("cancellation drains and reports nothing", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan error, 1)
		go func() { done <- Serve(ctx, srv, func() error { return srv.Serve(ln) }, "test", log) }()

		// Reachable first, so this is a shutdown and not a failed bind.
		resp, err := http.Get("http://" + ln.Addr().String() + "/") //#nosec G107 -- this test's own loopback listener
		if err != nil {
			t.Fatalf("the listener never came up: %v", err)
		}
		_ = resp.Body.Close()

		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("a clean shutdown reported %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Serve did not return after cancellation")
		}
	})

	t.Run("an accept failure is returned", func(t *testing.T) {
		srv := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
		want := errors.New("address already in use")
		err := Serve(context.Background(), srv, func() error { return want }, "test", log)
		if !errors.Is(err, want) {
			t.Errorf("Serve returned %v, want %v", err, want)
		}
	})

	t.Run("a closed server is not a failure", func(t *testing.T) {
		// What srv.Serve returns once Shutdown has run. It reaches the same
		// branch as a real failure and must not be reported as one, or every
		// clean stop logs an error.
		srv := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
		if err := Serve(context.Background(), srv, func() error { return http.ErrServerClosed }, "test", log); err != nil {
			t.Errorf("ErrServerClosed was reported as %v", err)
		}
	})
}
