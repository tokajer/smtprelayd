// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/store"
)

// seedMessages writes n history rows, newest first, so a page boundary can be
// crossed without a spool.
func seedMessages(t *testing.T, st *store.Store, n int) {
	t.Helper()
	now := time.Now().UTC()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("QPAGE%021d", i)
		if err := st.RecordMessage(store.MessageRecord{
			QueueID: id, Client: "printers", Route: "m365",
			EnvelopeFrom: "device@example.at", Recipients: `["x@example.net"]`,
			Listener: "smtp", RemoteAddr: "10.10.5.9",
			ReceivedAt: now.Add(-time.Duration(i) * time.Minute),
			ExpiresAt:  now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// The pager is the only way past the first 50 rows, and until this test the
// arithmetic behind it was covered by nothing: pageLinks could stop emitting
// the "older" link entirely and every test still passed. A queue longer than
// one page with no way to reach the rest is a dashboard that quietly hides
// mail.
//
// The assertions read the pager block itself, not the whole page: "older"
// also occurs in the sort and filter controls, so a whole-body match would
// pass for the wrong reason.
var pagerBlock = regexp.MustCompile(`(?s)<div class="pager">(.*?)</div>`)

func pager(t *testing.T, h http.Handler, target string) string {
	t.Helper()
	rec := get(t, h, target)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s returned %d", target, rec.Code)
	}
	m := pagerBlock.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("%s rendered no pager at all", target)
	}
	return m[1]
}

func TestPagerOffersTheNextPageAndThenBack(t *testing.T) {
	srv, st, _ := testServer(t, testConfig(t, ""))
	seedMessages(t, st, pageSize+1)

	for _, path := range []string{"/queue", "/search"} {
		t.Run(path, func(t *testing.T) {
			next := fmt.Sprintf("%s?offset=%d", path, pageSize)

			first := pager(t, srv.Handler(), path)
			if !strings.Contains(first, `href="`+next+`"`) {
				t.Errorf("first page does not link to %s: %q", next, first)
			}
			if strings.Contains(first, "newer") {
				t.Errorf("first page offers a link to a page before it: %q", first)
			}

			second := pager(t, srv.Handler(), next)
			// Back to offset 0, which pageHref writes as the bare path.
			if !strings.Contains(second, `href="`+path+`"`) {
				t.Errorf("second page does not link back to %s: %q", path, second)
			}
			if strings.Contains(second, "older") {
				t.Errorf("last page still offers a link onwards: %q", second)
			}
		})
	}
}
