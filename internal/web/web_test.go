// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/certgen"
	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	body := `
[service]
data_dir = "` + filepath.ToSlash(t.TempDir()) + `"

[[listener]]
name = "smtp"
address = "127.0.0.1:2525"
tls = "none"

[[client]]
name = "printers"
cidr = ["10.10.5.0/24"]
route = "m365"

[[route]]
name = "m365"
default = true
host = "smtp.example"
auth = "none"

[web]
address = "127.0.0.1:8025"
enabled = true
` + extra

	p := filepath.Join(t.TempDir(), "smtprelayd.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func testServer(t *testing.T, cfg *config.Config) (*Server, *store.Store, *spool.Spool) {
	t.Helper()
	st, err := store.Open(t.TempDir(), discardLog(), 90, cfg.History.RetainSubjects)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sp, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, st, sp, nil, "test", discardLog())
	if err != nil {
		t.Fatal(err)
	}
	return srv, st, sp
}

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	// httptest defaults the Host header to example.com, which the dashboard
	// now refuses; a real request carries the loopback address it was sent to.
	r.Host = "127.0.0.1:8080"
	h.ServeHTTP(rec, r)
	return rec
}

// A page the operator visits can point a name it controls at 127.0.0.1 and
// then talk to the dashboard same-origin, which is the whole loopback-is-the-
// authentication decision undone. The Host header is the only part of such a
// request that still carries the attacker's name.
func TestNonLoopbackHostHeaderIsRefused(t *testing.T) {
	cfg := testConfig(t, "")
	srv, _, _ := testServer(t, cfg)
	h := srv.Handler()

	for _, host := range []string{
		"rebind.attacker.example",
		"rebind.attacker.example:8080",
		"127.0.0.1.attacker.example",
		"example.com",
	} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/config", nil)
		r.Host = host
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: status %d, want %d", host, rec.Code, http.StatusMisdirectedRequest)
		}
		if strings.Contains(rec.Body.String(), "oauth2") {
			t.Errorf("Host %q: the config page was rendered anyway", host)
		}
	}

	for _, host := range []string{"127.0.0.1", "127.0.0.1:8080", "localhost", "localhost:8080", "[::1]", "[::1]:8080"} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/config", nil)
		r.Host = host
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Errorf("Host %q: status %d, want 200", host, rec.Code)
		}
	}
}

func TestSecurityHeadersOnEveryPage(t *testing.T) {
	cfg := testConfig(t, "")
	srv, _, _ := testServer(t, cfg)
	h := srv.Handler()

	for _, path := range []string{"/queue", "/search", "/bounces", "/routes", "/config"} {
		rec := get(t, h, path)
		for header, want := range map[string]string{
			"Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
			"X-Content-Type-Options":  "nosniff",
			"X-Frame-Options":         "DENY",
			"Referrer-Policy":         "strict-origin-when-cross-origin",
		} {
			if got := rec.Header().Get(header); got != want {
				t.Errorf("%s: header %s = %q, want %q", path, header, got, want)
			}
		}
	}
}

func TestRootRedirectsToQueue(t *testing.T) {
	cfg := testConfig(t, "")
	srv, _, _ := testServer(t, cfg)
	rec := get(t, srv.Handler(), "/")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/queue" {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestXSSShapedSubjectIsEscaped(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, _ := testServer(t, cfg)

	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	const evilSubject = `<script>alert(1)</script><img src=x onerror=alert(2)>`
	// The journal fields carry client-supplied text just like the subject
	// does, so they are filled with the same payload here rather than
	// trusting that a header is somehow safer than a subject.
	if err := st.RecordMessage(store.MessageRecord{
		QueueID: "XSSTESTAAAAAAAAA", Client: "printers", Route: "m365",
		EnvelopeFrom: "relay@example.com", Recipients: string(recipients),
		Subject: evilSubject, Listener: "smtp", RemoteAddr: "10.10.5.5",
		MessageID: evilSubject, ContentType: evilSubject, Helo: evilSubject,
		SizeBytes: 2048, HeaderCount: 7,
		ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/queue", "/search", "/messages/XSSTESTAAAAAAAAA"} {
		t.Run(path, func(t *testing.T) {
			rec := get(t, srv.Handler(), path)
			body := rec.Body.String()
			// The only markup this response is allowed to contain is the
			// dashboard's own, so any literal opening tag is a sign the
			// subject broke out of its escaped text context.
			if strings.Contains(body, "<script>") || strings.Contains(body, "<img") {
				t.Fatalf("unescaped tag from the subject survived into the response (status %d):\n%s", rec.Code, body)
			}
			if !strings.Contains(body, "&lt;script&gt;") {
				t.Fatalf("expected the escaped subject to be present (status %d):\n%s", rec.Code, body)
			}
		})
	}
}

func TestSubjectRedactedWhenRetentionDisabled(t *testing.T) {
	cfg := testConfig(t, "\n[history]\nretention_days = 90\nretain_subjects = false\n")
	srv, st, _ := testServer(t, cfg)

	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	// store.RecordMessage itself already redacts when retain_subjects is
	// false, so this proves the display layer's fallback matches, not that
	// it does the only redaction.
	if err := st.RecordMessage(store.MessageRecord{QueueID: "REDACTEDAAAAAAAA", Client: "printers", Route: "m365", EnvelopeFrom: "relay@example.com", OriginalFrom: "", Recipients: string(recipients), Subject: "should never appear", Listener: "smtp", RemoteAddr: "10.10.5.5", ReceivedAt: now, ExpiresAt: now.Add(time.Hour), TLSUsed: false}); err != nil {
		t.Fatal(err)
	}

	rec := get(t, srv.Handler(), "/messages/REDACTEDAAAAAAAA")
	body := rec.Body.String()
	if strings.Contains(body, "should never appear") {
		t.Fatalf("subject leaked despite retain_subjects=false:\n%s", body)
	}
	if !strings.Contains(body, "[redacted]") {
		t.Fatalf("expected [redacted] marker:\n%s", body)
	}
}

func TestMessageHandlerRejectsInvalidQueueID(t *testing.T) {
	cfg := testConfig(t, "")
	srv, _, _ := testServer(t, cfg)

	// Wrong length, wrong alphabet (lowercase), and wrong alphabet (digits
	// the Crockford-style ID encoding never produces) respectively — none of
	// these are URL-special, so they exercise ParseID without also
	// exercising net/http's own path-cleaning redirect for "..".
	for _, id := range []string{"short", "abcdefghijklmnop", "0000000000000000"} {
		rec := get(t, srv.Handler(), "/messages/"+id)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("id %q: status = %d, want 400", id, rec.Code)
		}
	}
}

func TestMessageHandlerReportsMissingMessage(t *testing.T) {
	cfg := testConfig(t, "")
	srv, _, _ := testServer(t, cfg)
	// A syntactically valid but unknown queue ID must render a clean "not
	// found" page, not a server error.
	rec := get(t, srv.Handler(), "/messages/AAAAAAAAAAAAAAAA")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with a not-found message", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not found") {
		t.Fatalf("expected a not-found message:\n%s", rec.Body.String())
	}
}

func TestQueueStatusFilterOnlyShowsActiveMessages(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, _ := testServer(t, cfg)

	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	_ = st.RecordMessage(store.MessageRecord{QueueID: "QUEUEDAAAAAAAAAA", Client: "printers", Route: "m365", EnvelopeFrom: "relay@example.com", OriginalFrom: "", Recipients: string(recipients), Subject: "still queued", Listener: "smtp", RemoteAddr: "10.10.5.5", ReceivedAt: now, ExpiresAt: now.Add(time.Hour), TLSUsed: false})
	_ = st.RecordMessage(store.MessageRecord{QueueID: "DELIVEREDAAAAAAA", Client: "printers", Route: "m365", EnvelopeFrom: "relay@example.com", OriginalFrom: "", Recipients: string(recipients), Subject: "already gone", Listener: "smtp", RemoteAddr: "10.10.5.5", ReceivedAt: now, ExpiresAt: now.Add(time.Hour), TLSUsed: false})
	_ = st.RecordAttempt("DELIVEREDAAAAAAA", 1, 250, "ok", "delivered", nil)

	rec := get(t, srv.Handler(), "/queue")
	body := rec.Body.String()
	if !strings.Contains(body, "still queued") {
		t.Errorf("queue view is missing an active message:\n%s", body)
	}
	if strings.Contains(body, "already gone") {
		t.Errorf("queue view shows an already-delivered message:\n%s", body)
	}
}

func TestSearchInvalidTimeRangeShowsErrorNotCrash(t *testing.T) {
	cfg := testConfig(t, "")
	srv, _, _ := testServer(t, cfg)
	rec := get(t, srv.Handler(), "/search?since=not-a-date")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with an inline error", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "RFC 3339") {
		t.Fatalf("expected a validation message:\n%s", rec.Body.String())
	}
}

func TestConfigViewNeverRendersAResolvedSecret(t *testing.T) {
	const secretEnv = "SMTPRELAYD_TEST_WEB_SECRET"
	const secretValue = "S3cretValueThatMustNeverAppear"
	t.Setenv(secretEnv, secretValue)

	cfg := testConfig(t, fmt.Sprintf(`
[[route]]
name = "oauth-route"
host = "smtp.office365.com"
auth = "xoauth2"
oauth2.tenant_id = "contoso.onmicrosoft.com"
oauth2.client_id = "00000000-0000-0000-0000-000000000000"
oauth2.client_secret = "${%s}"
oauth2.mailbox = "relay@contoso.onmicrosoft.com"
`, secretEnv))

	// Confirm the secret really did resolve, so the test is not vacuous.
	var resolved bool
	for _, r := range cfg.Routes {
		if r.Name == "oauth-route" && r.OAuth2.ClientSecret.Value() == secretValue {
			resolved = true
		}
	}
	if !resolved {
		t.Fatal("test setup failed: secret did not resolve to the expected value")
	}

	srv, _, _ := testServer(t, cfg)
	rec := get(t, srv.Handler(), "/config")
	body := rec.Body.String()
	if strings.Contains(body, secretValue) {
		t.Fatalf("resolved secret leaked into the config view:\n%s", body)
	}
	if !strings.Contains(body, "[redacted]") {
		t.Fatalf("expected the oauth2 route to show [redacted]:\n%s", body)
	}
}

func TestMessagePageIncludesCSRFTokens(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, _ := testServer(t, cfg)
	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	if err := st.RecordMessage(store.MessageRecord{QueueID: "CSRFPAGEAAAAAAAA", Client: "printers", Route: "m365", EnvelopeFrom: "relay@example.com", OriginalFrom: "", Recipients: string(recipients), Subject: "s", Listener: "smtp", RemoteAddr: "10.10.5.5", ReceivedAt: now, ExpiresAt: now.Add(time.Hour), TLSUsed: false}); err != nil {
		t.Fatal(err)
	}

	body := get(t, srv.Handler(), "/messages/CSRFPAGEAAAAAAAA").Body.String()
	if !strings.Contains(body, `action="/messages/CSRFPAGEAAAAAAAA/requeue"`) ||
		!strings.Contains(body, `action="/messages/CSRFPAGEAAAAAAAA/delete"`) {
		t.Fatalf("requeue/delete forms missing:\n%s", body)
	}
	if strings.Count(body, `name="csrf" value="`) != 2 {
		t.Fatalf("expected two distinct CSRF tokens (requeue and delete):\n%s", body)
	}
}

// TestMessagePageHidesActionsForTerminalStatus guards against a click-through
// to a guaranteed 404: once a message has been delivered or removed, both
// spool.Remove and spool.Discard have already deleted its spool files for
// good, so Requeue and Delete can never succeed again.
func TestMessagePageHidesActionsForTerminalStatus(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, _ := testServer(t, cfg)
	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()

	for _, tc := range []struct {
		id, class string
	}{
		{"TERMDELIVERED222", "delivered"},
		{"TERMREMOVED22222", "removed"},
	} {
		if err := st.RecordMessage(store.MessageRecord{QueueID: tc.id, Client: "printers", Route: "m365", EnvelopeFrom: "relay@example.com", Recipients: string(recipients), Subject: "s", Listener: "smtp", RemoteAddr: "10.10.5.5", ReceivedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := st.RecordAttempt(tc.id, 1, 0, "", tc.class, nil); err != nil {
			t.Fatal(err)
		}

		body := get(t, srv.Handler(), "/messages/"+tc.id).Body.String()
		if strings.Contains(body, `action="/messages/`+tc.id+`/requeue"`) ||
			strings.Contains(body, `action="/messages/`+tc.id+`/delete"`) {
			t.Fatalf("status %q: requeue/delete forms still rendered:\n%s", tc.class, body)
		}
		if !strings.Contains(body, "nothing left in the spool") {
			t.Fatalf("status %q: expected explanatory text, got:\n%s", tc.class, body)
		}
	}
}

func postForm(h http.Handler, target, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestRequeueActionRejectsMissingOrWrongCSRF(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, sp := testServer(t, cfg)
	id := enqueueMessage(t, st, sp, "m365")

	if rec := postForm(srv.Handler(), "/messages/"+id+"/requeue", ""); rec.Code != http.StatusForbidden {
		t.Errorf("empty token: status = %d, want 403", rec.Code)
	}
	// A token issued for the delete action must not authorise a requeue.
	wrongAction := srv.csrf.token("delete", id, time.Now())
	if rec := postForm(srv.Handler(), "/messages/"+id+"/requeue", wrongAction); rec.Code != http.StatusForbidden {
		t.Errorf("cross-action token: status = %d, want 403", rec.Code)
	}
	// A token issued for a different message must not authorise this one.
	otherID := "OTHERMSGAAAAAAAA"
	wrongTarget := srv.csrf.token("requeue", otherID, time.Now())
	if rec := postForm(srv.Handler(), "/messages/"+id+"/requeue", wrongTarget); rec.Code != http.StatusForbidden {
		t.Errorf("cross-message token: status = %d, want 403", rec.Code)
	}
	expired := srv.csrf.token("requeue", id, time.Now().Add(-2*time.Hour))
	if rec := postForm(srv.Handler(), "/messages/"+id+"/requeue", expired); rec.Code != http.StatusForbidden {
		t.Errorf("expired token: status = %d, want 403", rec.Code)
	}
}

func TestRequeueActionSucceedsAndAudits(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, sp := testServer(t, cfg)
	id := enqueueMessage(t, st, sp, "m365")

	token := srv.csrf.token("requeue", id, time.Now())
	rec := postForm(srv.Handler(), "/messages/"+id+"/requeue", token)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	entries, err := st.FindAuditByQueueID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "requeue" || entries[0].TokenName != "dashboard" {
		t.Fatalf("unexpected audit entries: %+v", entries)
	}
}

func TestDeleteActionRemovesFromSpoolKeepsHistory(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, sp := testServer(t, cfg)
	id := enqueueMessage(t, st, sp, "m365")

	token := srv.csrf.token("delete", id, time.Now())
	rec := postForm(srv.Handler(), "/messages/"+id+"/delete", token)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if sp.Len() != 0 {
		t.Fatalf("spool still has %d messages after delete", sp.Len())
	}
	msg, err := st.FindMessageByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		t.Fatal("history row deleted along with the spool entry; delete must retain history")
	}
	if msg.Status != "removed" {
		t.Fatalf("status = %q, want removed", msg.Status)
	}

	active, _, err := st.FindMessages(store.MessageFilter{Status: "active", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range active {
		if m.QueueID == id {
			t.Fatal("deleted message still matches the /queue active filter")
		}
	}
}

// enqueueMessage puts one message in both the spool and the history store,
// as the listener does, so the requeue/delete action handlers (which act on
// the spool but audit against the store) have both to work with.
func enqueueMessage(t *testing.T, st *store.Store, sp *spool.Spool, route string) string {
	t.Helper()
	id, err := sp.Enqueue(spool.Envelope{
		From: "a@example.at", To: []string{"b@example.net"}, Route: route, Received: time.Now().UTC(),
	}, strings.NewReader("Subject: x\r\n\r\nbody\r\n"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	recipients, _ := json.Marshal([]string{"b@example.net"})
	if err := st.RecordMessage(store.MessageRecord{QueueID: id.String(), Client: "client", Route: route, EnvelopeFrom: "a@example.at", OriginalFrom: "", Recipients: string(recipients), Subject: "Test", Listener: "smtp", RemoteAddr: "10.0.0.1", ReceivedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), TLSUsed: false}); err != nil {
		t.Fatal(err)
	}
	return id.String()
}

// postValues drives the bulk endpoints, whose body carries the selection as
// repeated "id" fields plus a per-action token, rather than the single
// "csrf" field postForm sends.
func postValues(h http.Handler, target string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// recordGhost puts a message in the history store with no spool copy behind
// it: the state a manual deletion of the spool files, or a startup recovery
// that dropped a half-written pair, leaves behind.
func recordGhost(t *testing.T, st *store.Store, id string) string {
	t.Helper()
	recipients, _ := json.Marshal([]string{"b@example.net"})
	now := time.Now()
	if err := st.RecordMessage(store.MessageRecord{
		QueueID: id, Client: "printers", Route: "m365", EnvelopeFrom: "a@example.at",
		Recipients: string(recipients), Subject: "ghost", Listener: "smtp",
		RemoteAddr: "10.10.5.5", ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestQueuePageRendersBulkForm(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, sp := testServer(t, cfg)
	id := enqueueMessage(t, st, sp, "m365")

	body := get(t, srv.Handler(), "/queue").Body.String()
	for _, want := range []string{
		`name="id" value="` + id + `"`,
		`data-select-all`,
		`name="csrf_requeue"`,
		`name="csrf_delete"`,
		`name="scope" value="selected"`,
		`name="scope" value="all"`,
		// The whole-queue delete is a real submit button, not a link: it
		// reaches its own GET form by the `form` attribute, because that
		// form cannot be nested inside the bulk form.
		`form="confirm-delete-all"`,
		`<form method="get" action="/queue" id="confirm-delete-all" hidden>`,
		`/static/queue.js`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the queue page is missing %q", want)
		}
	}
}

// A row the spool no longer holds is marked, because requeue cannot do
// anything for it and the operator otherwise has no way to tell it apart
// from a message that is genuinely waiting to be sent.
func TestQueuePageMarksRowsWithNoSpoolCopy(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, sp := testServer(t, cfg)
	live := enqueueMessage(t, st, sp, "m365")
	recordGhost(t, st, "GHOSTAAAAAAAAAAA")

	body := get(t, srv.Handler(), "/queue").Body.String()
	if strings.Count(body, "no spool copy") != 1 {
		t.Fatalf("expected exactly one stale marker, body:\n%s", body)
	}
	if !strings.Contains(body, live) {
		t.Error("the live message vanished from the queue view")
	}
}

func TestQueueBulkRejectsMissingOrWrongCSRF(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, sp := testServer(t, cfg)
	id := enqueueMessage(t, st, sp, "m365")
	now := time.Now()

	for name, form := range map[string]url.Values{
		"no token":          {"scope": {"selected"}, "id": {id}},
		"wrong field":       {"scope": {"selected"}, "id": {id}, "csrf_delete": {srv.csrf.token("queue-delete", "", now)}},
		"single-msg token":  {"scope": {"selected"}, "id": {id}, "csrf_requeue": {srv.csrf.token("requeue", id, now)}},
		"other bulk action": {"scope": {"selected"}, "id": {id}, "csrf_requeue": {srv.csrf.token("queue-delete", "", now)}},
		"expired":           {"scope": {"selected"}, "id": {id}, "csrf_requeue": {srv.csrf.token("queue-requeue", "", now.Add(-2*time.Hour))}},
	} {
		if rec := postValues(srv.Handler(), "/queue/requeue", form); rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", name, rec.Code)
		}
	}
	if sp.Len() != 1 {
		t.Fatalf("spool changed despite every request being refused")
	}
}

func TestQueueBulkDeleteRemovesOnlySelected(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, sp := testServer(t, cfg)
	keep := enqueueMessage(t, st, sp, "m365")
	gone1 := enqueueMessage(t, st, sp, "m365")
	gone2 := enqueueMessage(t, st, sp, "m365")

	rec := postValues(srv.Handler(), "/queue/delete", url.Values{
		"csrf_delete": {srv.csrf.token("queue-delete", "", time.Now())},
		"scope":       {"selected"},
		"id":          {gone1, gone2},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "done=delete") || !strings.Contains(loc, "ok=2") {
		t.Fatalf("Location = %q, want the delete outcome", loc)
	}
	if sp.Len() != 1 {
		t.Fatalf("spool holds %d messages, want only the unselected one", sp.Len())
	}
	for _, id := range []string{gone1, gone2} {
		msg, err := st.FindMessageByID(id)
		if err != nil {
			t.Fatal(err)
		}
		if msg == nil || msg.Status != "removed" {
			t.Fatalf("%s: history row is %+v, want a retained row with status removed", id, msg)
		}
	}
	msg, err := st.FindMessageByID(keep)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Status != "queued" {
		t.Fatalf("unselected message status = %q, want queued", msg.Status)
	}
}

func TestQueueBulkRequeueSelectedAudits(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, sp := testServer(t, cfg)
	id := enqueueMessage(t, st, sp, "m365")

	rec := postValues(srv.Handler(), "/queue/requeue", url.Values{
		"csrf_requeue": {srv.csrf.token("queue-requeue", "", time.Now())},
		"scope":        {"selected"},
		"id":           {id},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	entries, err := st.FindAuditByQueueID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "requeue" || entries[0].Details != "bulk (selected)" {
		t.Fatalf("unexpected audit entries: %+v", entries)
	}
}

// The whole-queue delete is the one irreversible action on the page, so the
// form that carries it is only rendered behind the confirmation page and the
// handler refuses an unconfirmed request outright.
func TestQueueBulkDeleteAllRequiresConfirmation(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, sp := testServer(t, cfg)
	enqueueMessage(t, st, sp, "m365")
	enqueueMessage(t, st, sp, "m365")
	token := srv.csrf.token("queue-delete", "", time.Now())

	rec := postValues(srv.Handler(), "/queue/delete", url.Values{
		"csrf_delete": {token}, "scope": {"all"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed: status = %d, want 400", rec.Code)
	}
	if sp.Len() != 2 {
		t.Fatalf("unconfirmed request deleted %d messages", 2-sp.Len())
	}

	page := get(t, srv.Handler(), "/queue?confirm=delete-all").Body.String()
	if !strings.Contains(page, `value="delete-all"`) {
		t.Fatalf("the confirmation page does not carry the confirmed form:\n%s", page)
	}

	rec = postValues(srv.Handler(), "/queue/delete", url.Values{
		"csrf_delete": {token}, "scope": {"all"}, "confirm": {"delete-all"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("confirmed: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if sp.Len() != 0 {
		t.Fatalf("spool still holds %d messages after deleting the whole queue", sp.Len())
	}
	active, _, err := st.FindMessages(store.MessageFilter{Status: "active", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("%d messages still match the queue view", len(active))
	}
}

// The bug this whole path exists for: a message listed in the queue with no
// spool copy behind it answered 404 on every delete, so it could never be
// cleared from the view. Both the single-message action and the bulk one
// must now clear it.
func TestDeleteClearsAQueueRowWithNoSpoolCopy(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, _ := testServer(t, cfg)
	single := recordGhost(t, st, "GHOSTSINGLEAAAAA")
	bulk := recordGhost(t, st, "GHOSTBULKAAAAAAA")

	rec := postForm(srv.Handler(), "/messages/"+single+"/delete", srv.csrf.token("delete", single, time.Now()))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("single delete: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = postValues(srv.Handler(), "/queue/delete", url.Values{
		"csrf_delete": {srv.csrf.token("queue-delete", "", time.Now())},
		"scope":       {"selected"},
		"id":          {bulk},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("bulk delete: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "cleared=1") {
		t.Fatalf("Location = %q, want cleared=1", loc)
	}

	for _, id := range []string{single, bulk} {
		msg, err := st.FindMessageByID(id)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Status != "removed" {
			t.Fatalf("%s: status = %q, want removed", id, msg.Status)
		}
		entries, err := st.FindAuditByQueueID(id)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 || !strings.Contains(entries[0].Details, "no spool copy") {
			t.Fatalf("%s: unexpected audit entries: %+v", id, entries)
		}
	}

	// A queue ID that was never seen at all is still a 404: reconciliation
	// repairs a record that exists, it does not invent one.
	unknown := "NOSUCHMESSAGEAAA"
	rec = postForm(srv.Handler(), "/messages/"+unknown+"/delete", srv.csrf.token("delete", unknown, time.Now()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown message: status = %d, want 404", rec.Code)
	}
}

// A message whose spool copy is gone cannot be requeued: there is no body to
// send. It must be reported as missing rather than silently counted as done.
func TestQueueBulkRequeueReportsMessagesWithNoSpoolCopy(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, _ := testServer(t, cfg)
	id := recordGhost(t, st, "GHOSTREQUEUEAAAA")

	rec := postValues(srv.Handler(), "/queue/requeue", url.Values{
		"csrf_requeue": {srv.csrf.token("queue-requeue", "", time.Now())},
		"scope":        {"selected"},
		"id":           {id},
	})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "missing=1") {
		t.Fatalf("Location = %q, want missing=1", loc)
	}
	msg, err := st.FindMessageByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Status != "queued" {
		t.Fatalf("status = %q; a failed requeue must not rewrite the record", msg.Status)
	}
}

func TestQueueBulkRejectsMalformedRequests(t *testing.T) {
	cfg := testConfig(t, "")
	srv, _, _ := testServer(t, cfg)
	token := srv.csrf.token("queue-delete", "", time.Now())

	cases := map[string]url.Values{
		"unknown scope": {"csrf_delete": {token}, "scope": {"everything"}},
		"missing scope": {"csrf_delete": {token}},
		"invalid id":    {"csrf_delete": {token}, "scope": {"selected"}, "id": {"../../etc/passwd"}},
		"short id":      {"csrf_delete": {token}, "scope": {"selected"}, "id": {"TOOSHORT"}},
	}
	for name, form := range cases {
		if rec := postValues(srv.Handler(), "/queue/delete", form); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}

	tooMany := url.Values{"csrf_delete": {token}, "scope": {"selected"}}
	for i := 0; i <= bulkMax; i++ {
		tooMany.Add("id", "AAAAAAAAAAAAAAAA")
	}
	if rec := postValues(srv.Handler(), "/queue/delete", tooMany); rec.Code != http.StatusBadRequest {
		t.Errorf("over the cap: status = %d, want 400", rec.Code)
	}
}

// The banner is rebuilt from the redirect's query string, so it must never
// render text that came in with the request, and an unknown action must
// produce no banner at all.
func TestBulkFlashIsBuiltFromCountsOnly(t *testing.T) {
	if f := bulkFlash(url.Values{"done": {"<script>alert(1)</script>"}, "ok": {"1"}}); f != nil {
		t.Fatalf("an unknown action produced a banner: %+v", f)
	}
	if f := bulkFlash(url.Values{}); f != nil {
		t.Fatalf("no action produced a banner: %+v", f)
	}

	f := bulkFlash(url.Values{"done": {"delete"}, "ok": {"3"}, "cleared": {"2"}})
	if f == nil || f.Level != "ok" || !strings.Contains(f.Text, "3 deleted") || !strings.Contains(f.Text, "2 had no spool copy") {
		t.Fatalf("unexpected banner: %+v", f)
	}
	f = bulkFlash(url.Values{"done": {"requeue"}, "busy": {"1"}, "failed": {"2"}, "more": {"1"}})
	if f == nil || f.Level != "warn" || !strings.Contains(f.Text, "repeat the action") {
		t.Fatalf("unexpected banner: %+v", f)
	}
	f = bulkFlash(url.Values{"done": {"requeue"}})
	if f == nil || f.Level != "warn" || !strings.Contains(f.Text, "No message was selected") {
		t.Fatalf("unexpected empty-selection banner: %+v", f)
	}
	// Garbage in a count is read as zero, never echoed.
	f = bulkFlash(url.Values{"done": {"delete"}, "ok": {"<img src=x>"}})
	if f == nil || strings.Contains(f.Text, "img") {
		t.Fatalf("a count was echoed into the banner: %+v", f)
	}
}

func TestQueueScriptServedWithJSContentType(t *testing.T) {
	cfg := testConfig(t, "")
	srv, _, _ := testServer(t, cfg)
	rec := get(t, srv.Handler(), "/static/queue.js")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Fatalf("content-type = %q", ct)
	}
	// The CSP allows no inline script and no eval, so the page's own script
	// must not need either.
	if body := rec.Body.String(); strings.Contains(body, "eval(") || strings.Contains(body, "new Function") {
		t.Fatal("queue.js uses eval, which the dashboard's CSP forbids")
	}
}

func TestStyleServedWithCSSContentType(t *testing.T) {
	cfg := testConfig(t, "")
	srv, _, _ := testServer(t, cfg)
	rec := get(t, srv.Handler(), "/static/style.css")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("content-type = %q", ct)
	}
}

// TestServeIsPlainHTTPEvenWithATLSCertificateConfigured guards the fix for a
// real trap: Serve used to switch to HTTPS whenever cfg.TLS.CertFile was
// non-empty, and that field is populated as soon as any *SMTP* listener uses
// TLS. Configuring mail TLS therefore turned the dashboard into HTTPS on
// loopback, and an operator following CONFIGURATION.md to http://127.0.0.1
// got a handshake error. config.Validate pins web.address to loopback, so
// there is no address a certificate could authenticate to.
func TestServeIsPlainHTTPEvenWithATLSCertificateConfigured(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	cfg := testConfig(t, "")
	cfg.Web.Address = addr
	// A path that does not exist: the removed branch would have failed here
	// trying to load it, which is itself the regression this catches.
	cfg.TLS.CertFile = filepath.Join(t.TempDir(), "absent.crt")
	cfg.TLS.KeyFile = filepath.Join(t.TempDir(), "absent.key")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := Listen(cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "dashboard")
		}), discardLog())
	}()

	var resp *http.Response
	for i := 0; i < 100; i++ {
		resp, err = http.Get("http://" + addr + "/")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("plain HTTP GET failed, which is what serving TLS here would look like: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "dashboard" {
		t.Fatalf("body = %q, want %q", body, "dashboard")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve returned %v, want nil on a cancelled context", err)
	}
}

// The configuration page shows every deadline, not only the ones close enough to be
// mailed about: an operator checking whether the certificate is healthy needs
// to see it when it is.
func TestConfigPageShowsExpiries(t *testing.T) {
	cfg := testConfig(t, "")
	certPEM, _, err := certgen.Generate(certgen.Options{
		Hosts: []string{"relay.internal.example.at"}, Validity: 400 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(t.TempDir(), "relay.crt")
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.TLS.CertFile = certFile
	cfg.Routes = append(cfg.Routes, config.Route{
		Name: "m365", Auth: "xoauth2",
		OAuth2: config.OAuth2{
			TenantID:      "contoso.onmicrosoft.com",
			SecretExpires: time.Now().Add(10 * 24 * time.Hour).Format("2006-01-02"),
		},
	})

	srv, _, _ := testServer(t, cfg)
	body := get(t, srv.Handler(), "/config").Body.String()
	for _, want := range []string{
		"Expiry",
		"the listener TLS certificate",
		"the Microsoft 365 client secret for route &#34;m365&#34;",
		// 400 days out: present, and not flagged as a problem.
		"pill-ok",
		// 10 days out: inside the warning window.
		"pill-soon",
		"bounce.notify",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("config page is missing %q", want)
		}
	}
}

// A certificate path that cannot be read is surfaced, not silently omitted:
// it means the file changed under a running service.
func TestConfigPageReportsAnUnreadableCertificate(t *testing.T) {
	cfg := testConfig(t, "")
	cfg.TLS.CertFile = filepath.Join(t.TempDir(), "absent.crt")

	srv, _, _ := testServer(t, cfg)
	body := get(t, srv.Handler(), "/config").Body.String()
	if !strings.Contains(body, "could not be read") {
		t.Errorf("config page should report the unreadable certificate:\n%s", body)
	}
}

// A bulk action whose client has gone must stop rather than finish an
// irreversible run nobody will see the result of, and must report that it
// stopped so the operator knows to repeat it.
func TestQueueBulkStopsWhenTheClientDisconnects(t *testing.T) {
	cfg := testConfig(t, "")
	srv, st, sp := testServer(t, cfg)
	var ids []string
	for i := 0; i < 5; i++ {
		ids = append(ids, enqueueMessage(t, st, sp, "m365"))
	}

	form := url.Values{
		"csrf_delete": {srv.csrf.token("queue-delete", "", time.Now())},
		"scope":       {"selected"},
		"id":          ids,
	}
	req := httptest.NewRequest(http.MethodPost, "/queue/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "127.0.0.1:8025"

	// Already cancelled: the loop must stop before the first message rather
	// than finish an irreversible run whose result nobody will see.
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	q, err := url.ParseQuery(strings.TrimPrefix(loc, "/queue?"))
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("more") != "1" {
		t.Errorf("the redirect does not report an incomplete run: %q", loc)
	}
	if q.Get("ok") != "" {
		t.Errorf("messages were deleted despite a cancelled request: ok=%s", q.Get("ok"))
	}
	if n := sp.Len(); n != 5 {
		t.Errorf("spool holds %d messages, want all 5 untouched", n)
	}
}

// The banner has to tell the operator to repeat it, whichever bound was hit.
func TestBulkFlashReportsAnIncompleteRun(t *testing.T) {
	f := bulkFlash(url.Values{"done": {"delete"}, "ok": {"7"}, "more": {"1"}})
	if f == nil {
		t.Fatal("no banner")
	}
	if !strings.Contains(f.Text, "repeat the action") {
		t.Errorf("banner does not say to repeat it: %q", f.Text)
	}
	if !strings.Contains(f.Text, "7 deleted") {
		t.Errorf("banner does not report what was done: %q", f.Text)
	}
}

// Every listing on the dashboard is built from the history store, so a
// journal write that failed leaves a message in the spool and on no page
// here. The banner is the only place somebody looking at the queue, rather
// than at the log or at /metrics, learns that.
func TestJournalFailuresAreStatedOnThePage(t *testing.T) {
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
	reg := metrics.New(metrics.ConfigExpiry(cfg), sp, []string{"m365"}, nil, nil)
	srv, err := New(cfg, st, sp, reg, "test", discardLog())
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	if body := get(t, h, "/queue").Body.String(); strings.Contains(body, "history write(s) have failed") {
		t.Fatal("the banner is shown although no journal write has failed")
	}

	reg.JournalWriteFailure()
	reg.JournalWriteFailure()
	body := get(t, h, "/queue").Body.String()
	if !strings.Contains(body, "2 history write(s) have failed") {
		t.Fatalf("the queue page does not report the failed journal writes:\n%s", body)
	}
	// Every page is built from the same base data, so the warning has to
	// follow the operator rather than sit on the one page they left.
	if !strings.Contains(get(t, h, "/search").Body.String(), "history write(s) have failed") {
		t.Error("the search page does not carry the warning")
	}
}
