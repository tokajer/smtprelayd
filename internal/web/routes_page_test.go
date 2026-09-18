// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// metrics.RouteStatus's doc comment says it backs both the text exposition
// and this page, "so the two never disagree about what a route's state is".
// smtprelayd_recipients_refused_total was added to the exposition and not to
// this page, which broke exactly that promise: /metrics reported refused
// recipients that the dashboard did not show anywhere.
func TestRoutesPageShowsEveryRouteCounter(t *testing.T) {
	cfg := testConfig(t, "")
	st, err := store.Open(t.TempDir(), discardLog(), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sp, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	reg := metrics.New(cfg, sp, []string{"m365"}, nil, nil)
	reg.Delivered("m365")
	reg.RecipientsRefused("m365", 7)

	srv, err := New(cfg, st, sp, reg, "test", discardLog())
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/routes", nil)
	r.Host = "127.0.0.1"
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	if !strings.Contains(body, "Refused rcpts") {
		t.Error("the routes page has no column for refused recipients")
	}
	if !strings.Contains(body, ">7<") {
		t.Errorf("the refused count is not rendered; body:\n%s", body)
	}

	// Header and body cells have to stay in step, or every column after the
	// new one is shifted under the wrong heading.
	headers := strings.Count(body[strings.Index(body, "<thead>"):strings.Index(body, "</thead>")], "<th>")
	rowStart := strings.Index(body, "<tbody>")
	cells := strings.Count(body[rowStart:strings.Index(body, "</tbody>")], "<td")
	if headers != cells {
		t.Errorf("%d headers against %d cells in the row", headers, cells)
	}
}
