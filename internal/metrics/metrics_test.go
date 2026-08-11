// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/spool"
)

func TestNewSeedsZeroCountersForConfiguredRoutes(t *testing.T) {
	r := New(nil, []string{"m365", "legacy"}, nil)
	text := r.text()
	for _, want := range []string{
		`smtprelayd_delivered_total{route="legacy"} 0`,
		`smtprelayd_delivered_total{route="m365"} 0`,
		`smtprelayd_bounced_total{route="m365"} 0`,
		`smtprelayd_deferred_total{route="m365"} 0`,
		`smtprelayd_auth_failures_total{route="m365"} 0`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing zero-seeded line %q in:\n%s", want, text)
		}
	}
}

func TestCountersIncrementPerRoute(t *testing.T) {
	r := New(nil, []string{"m365"}, nil)
	r.Delivered("m365")
	r.Delivered("m365")
	r.Bounced("m365")
	r.Deferred("m365")
	r.AuthFailure("m365")

	text := r.text()
	for _, want := range []string{
		`smtprelayd_delivered_total{route="m365"} 2`,
		`smtprelayd_bounced_total{route="m365"} 1`,
		`smtprelayd_deferred_total{route="m365"} 1`,
		`smtprelayd_auth_failures_total{route="m365"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing line %q in:\n%s", want, text)
		}
	}
	if !strings.Contains(text, `smtprelayd_last_delivery_time{route="m365"}`) {
		t.Error("last_delivery_time missing after a delivery")
	}
}

func TestLastDeliveryTimeAbsentBeforeFirstDelivery(t *testing.T) {
	r := New(nil, []string{"m365"}, nil)
	text := r.text()
	if strings.Contains(text, `smtprelayd_last_delivery_time{route="m365"}`) {
		t.Error("last_delivery_time present before any delivery")
	}
}

func TestQueueSizeReflectsSpool(t *testing.T) {
	dir := t.TempDir()
	sp, err := spool.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sp.Enqueue(spool.Envelope{From: "a@example.at", To: []string{"b@example.net"}, Route: "m365"},
		strings.NewReader("x"), 0, 0); err != nil {
		t.Fatal(err)
	}

	r := New(sp, []string{"m365"}, nil)
	text := r.text()
	if !strings.Contains(text, `smtprelayd_queue_size{route="m365",state="queued"} 1`) {
		t.Errorf("queue size not reflected:\n%s", text)
	}
}

func TestStatusSnapshotMatchesCounters(t *testing.T) {
	r := New(nil, []string{"m365", "legacy"}, nil)
	r.Delivered("m365")
	r.Bounced("m365")
	r.Deferred("legacy")

	status := r.Status()
	if len(status) != 2 {
		t.Fatalf("got %d routes, want 2", len(status))
	}
	byRoute := map[string]RouteStatus{}
	for _, st := range status {
		byRoute[st.Route] = st
	}
	if got := byRoute["m365"]; got.Delivered != 1 || got.Bounced != 1 || got.LastDelivery.IsZero() {
		t.Errorf("m365 status = %+v", got)
	}
	if got := byRoute["legacy"]; got.DeferredTotal != 1 || got.HasToken {
		t.Errorf("legacy status = %+v", got)
	}
}

func TestRouteLabelIsEscaped(t *testing.T) {
	r := New(nil, []string{`evil"route`}, nil)
	text := r.text()
	if !strings.Contains(text, `smtprelayd_delivered_total{route="evil\"route"} 0`) {
		t.Errorf("route label not escaped:\n%s", text)
	}
}

func TestServeHTTPRejectsNonGet(t *testing.T) {
	r := New(nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestAPIAuthFailureIsUnlabeled(t *testing.T) {
	r := New(nil, []string{"m365"}, nil)
	r.APIAuthFailure()
	r.APIAuthFailure()
	text := r.text()
	if !strings.Contains(text, "smtprelayd_api_auth_failures_total 2") {
		t.Errorf("expected an unlabeled counter at 2:\n%s", text)
	}
}

func TestUptimeAdvances(t *testing.T) {
	r := New(nil, nil, nil)
	if r.Uptime() < 0 {
		t.Fatalf("Uptime is negative: %v", r.Uptime())
	}
}

func TestStatusIncludesOldestQueued(t *testing.T) {
	dir := t.TempDir()
	sp, err := spool.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if _, err := sp.Enqueue(spool.Envelope{From: "a@example.at", To: []string{"b@example.net"}, Route: "m365", Received: old},
		strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}

	r := New(sp, []string{"m365"}, nil)
	status := r.Status()
	if len(status) != 1 || !status[0].OldestQueued.Equal(old) {
		t.Fatalf("got %+v, want OldestQueued %v", status, old)
	}
}

func TestServeHTTPServesText(t *testing.T) {
	r := New(nil, []string{"m365"}, nil)
	r.Delivered("m365")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "smtprelayd_delivered_total") {
		t.Errorf("expected metric names in body:\n%s", rec.Body.String())
	}
}
