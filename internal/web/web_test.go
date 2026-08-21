// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
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
data_dir = "` + t.TempDir() + `"

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

	active, err := st.FindMessages(store.MessageFilter{Status: "active", Limit: 100})
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
