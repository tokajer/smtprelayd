// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// /api/v1/queue used to report a narrower view of a route than /metrics did:
// auth_failures was missing from the start, and recipients_refused_total was
// added to the exposition without being added here. The second one matters
// most, because a message with a refused recipient is delivered and so
// appears in no failure counter at all -- a caller polling the API instead of
// /metrics, which docs/guides/API.md presents as equally valid, could not see
// a dead address anywhere.
func TestQueueReportsEveryRouteCounter(t *testing.T) {
	srv, _, _ := testServer(t)
	srv.metrics.Delivered("m365")
	srv.metrics.Bounced("m365")
	srv.metrics.Deferred("m365")
	srv.metrics.AuthFailure("m365")
	srv.metrics.RecipientsRefused("m365", 4)

	rec := doReq(srv.Handler(), http.MethodGet, "/queue", readToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}

	var got struct {
		Routes []map[string]any `json:"routes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding the response: %v", err)
	}

	var m365 map[string]any
	for _, r := range got.Routes {
		if r["route"] == "m365" {
			m365 = r
		}
	}
	if m365 == nil {
		t.Fatalf("m365 absent from %s", rec.Body.String())
	}

	for field, want := range map[string]float64{
		"delivered_total":          1,
		"bounced_total":            1,
		"deferred_total":           1,
		"auth_failures_total":      1,
		"recipients_refused_total": 4,
	} {
		got, ok := m365[field]
		if !ok {
			t.Errorf("field %q is absent from the response", field)
			continue
		}
		if got != want {
			t.Errorf("field %q = %v, want %v", field, got, want)
		}
	}
}

// The API and the exposition have to agree, not merely both be non-empty:
// every counter metrics.Status carries about a route is one the two views
// are supposed to share.
func TestQueueAgreesWithTheMetricsSnapshot(t *testing.T) {
	srv, _, _ := testServer(t)
	srv.metrics.RecipientsRefused("legacy", 9)
	srv.metrics.AuthFailure("legacy")

	rec := doReq(srv.Handler(), http.MethodGet, "/queue", readToken)
	var got struct {
		Routes []map[string]any `json:"routes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}

	for _, st := range srv.metrics.Status() {
		var row map[string]any
		for _, r := range got.Routes {
			if r["route"] == st.Route {
				row = r
			}
		}
		if row == nil {
			t.Fatalf("route %q is in the metrics snapshot but not in the API response", st.Route)
		}
		if row["recipients_refused_total"] != float64(st.RecipientsRefused) {
			t.Errorf("route %q: API says %v refused, metrics says %d",
				st.Route, row["recipients_refused_total"], st.RecipientsRefused)
		}
		if row["auth_failures_total"] != float64(st.AuthFailures) {
			t.Errorf("route %q: API says %v auth failures, metrics says %d",
				st.Route, row["auth_failures_total"], st.AuthFailures)
		}
	}
}
