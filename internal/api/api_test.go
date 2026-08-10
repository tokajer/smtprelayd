// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

const (
	readToken  = "read-token-plaintext-000"
	adminToken = "admin-token-plaintext-00"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func digest(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

func testServer(t *testing.T) (*Server, *store.Store, *spool.Spool) {
	t.Helper()
	cfg := &config.Config{
		History: config.History{RetainSubjects: true},
		Routes: []config.Route{
			{Name: "m365", Auth: "xoauth2"},
			{Name: "legacy", Auth: "none"},
		},
		Web: config.Web{
			Tokens: []config.Token{
				{Name: "checkmk", Scope: "read", SHA256: digest(readToken)},
				{Name: "ops", Scope: "admin", SHA256: digest(adminToken)},
			},
		},
	}
	st, err := store.Open(t.TempDir(), discardLog(), 90, cfg.History.RetainSubjects)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sp, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reg := metrics.New(sp, []string{"m365", "legacy"}, nil)
	return New(cfg, st, sp, reg, "test", discardLog()), st, sp
}

func doReq(h http.Handler, method, target, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	// Distinct source addresses across independent test cases so the
	// package-level rate limiter's state from one test cannot bleed into
	// another via a shared "192.0.2.1:1234"-shaped default.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestHealthRequiresNoAuth(t *testing.T) {
	srv, _, _ := testServer(t)
	rec := doReq(srv.Handler(), http.MethodGet, "/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Status string `json:"status"`
		Routes []struct {
			Name          string `json:"name"`
			Authenticated bool   `json:"authenticated"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, rec.Body.String())
	}
	if body.Status != "ok" || len(body.Routes) != 2 {
		t.Fatalf("unexpected health body: %+v", body)
	}
	for _, r := range body.Routes {
		if r.Name == "m365" && r.Authenticated {
			t.Error("xoauth2 route with no token yet reported as authenticated")
		}
		if r.Name == "legacy" && !r.Authenticated {
			t.Error("non-xoauth2 route reported as not authenticated")
		}
	}
}

func TestMissingOrInvalidTokenIs401(t *testing.T) {
	srv, _, _ := testServer(t)
	h := srv.Handler()
	for _, token := range []string{"", "not-a-real-token", readToken + "x"} {
		rec := doReq(h, http.MethodGet, "/bounces", token)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q: status = %d, want 401", token, rec.Code)
		}
	}
}

func TestValidReadTokenCanRead(t *testing.T) {
	srv, _, _ := testServer(t)
	for _, target := range []string{"/bounces", "/messages", "/queue"} {
		rec := doReq(srv.Handler(), http.MethodGet, target, readToken)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200: %s", target, rec.Code, rec.Body.String())
		}
	}
}

func TestReadScopeCannotRequeueOrDelete(t *testing.T) {
	srv, st, sp := testServer(t)
	id := enqueueTestMessage(t, st, sp, "m365")

	rec := doReq(srv.Handler(), http.MethodPost, "/messages/"+id+"/requeue", readToken)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("requeue with read token: status = %d, want 403", rec.Code)
	}
	rec = doReq(srv.Handler(), http.MethodDelete, "/messages/"+id, readToken)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("delete with read token: status = %d, want 403", rec.Code)
	}
}

func TestAdminScopeCanRequeueAndAudits(t *testing.T) {
	srv, st, sp := testServer(t)
	id := enqueueTestMessage(t, st, sp, "m365")

	rec := doReq(srv.Handler(), http.MethodPost, "/messages/"+id+"/requeue", adminToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("requeue: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	entries, err := st.FindAuditByQueueID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "requeue" || entries[0].TokenName != "ops" {
		t.Fatalf("unexpected audit entries: %+v", entries)
	}
}

func TestAdminScopeCanDeleteAndAudits(t *testing.T) {
	srv, st, sp := testServer(t)
	id := enqueueTestMessage(t, st, sp, "m365")

	rec := doReq(srv.Handler(), http.MethodDelete, "/messages/"+id, adminToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: status = %d, body = %s", rec.Code, rec.Body.String())
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

	entries, err := st.FindAuditByQueueID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "delete" || entries[0].TokenName != "ops" {
		t.Fatalf("unexpected audit entries: %+v", entries)
	}
}

func TestRequeueUnknownIDReturns404(t *testing.T) {
	srv, _, _ := testServer(t)
	rec := doReq(srv.Handler(), http.MethodPost, "/messages/AAAAAAAAAAAAAAAA/requeue", adminToken)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestInvalidQueueIDIs400(t *testing.T) {
	srv, _, _ := testServer(t)
	for _, target := range []string{"/messages/short", "/messages/short/requeue"} {
		method := http.MethodGet
		if strings.HasSuffix(target, "requeue") {
			method = http.MethodPost
		}
		token := readToken
		if method == http.MethodPost {
			token = adminToken
		}
		rec := doReq(srv.Handler(), method, target, token)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", target, rec.Code)
		}
	}
}

func TestSQLShapedFilterIsTreatedAsLiteral(t *testing.T) {
	srv, st, sp := testServer(t)
	enqueueTestMessage(t, st, sp, "m365")

	rec := doReq(srv.Handler(), http.MethodGet, "/messages?recipient="+url.QueryEscape("' OR 1=1 --"), readToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Messages) != 0 {
		t.Fatalf("SQL-shaped filter matched %d rows, want 0", len(body.Messages))
	}
}

func TestUnknownStatusIsRejected(t *testing.T) {
	srv, _, _ := testServer(t)
	rec := doReq(srv.Handler(), http.MethodGet, "/messages?status=not-a-real-status", readToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCursorPaginationAdvances(t *testing.T) {
	srv, st, sp := testServer(t)
	for i := 0; i < 3; i++ {
		enqueueTestMessage(t, st, sp, "m365")
	}

	rec := doReq(srv.Handler(), http.MethodGet, "/messages?limit=2", readToken)
	var page1 struct {
		Messages   []json.RawMessage `json:"messages"`
		NextCursor *string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page1); err != nil {
		t.Fatal(err)
	}
	if len(page1.Messages) != 2 || page1.NextCursor == nil {
		t.Fatalf("page1: got %d messages, next_cursor=%v", len(page1.Messages), page1.NextCursor)
	}

	rec2 := doReq(srv.Handler(), http.MethodGet, "/messages?cursor="+*page1.NextCursor, readToken)
	var page2 struct {
		Messages   []json.RawMessage `json:"messages"`
		NextCursor *string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &page2); err != nil {
		t.Fatal(err)
	}
	if len(page2.Messages) != 1 || page2.NextCursor != nil {
		t.Fatalf("page2: got %d messages, next_cursor=%v", len(page2.Messages), page2.NextCursor)
	}
}

func TestRateLimitBlocksAfterRepeatedFailures(t *testing.T) {
	srv, _, _ := testServer(t)
	h := srv.Handler()

	r := httptest.NewRequest(http.MethodGet, "/bounces", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.Header.Set("Authorization", "Bearer wrong-token")

	var last *httptest.ResponseRecorder
	for i := 0; i < failThreshold+1; i++ {
		last = httptest.NewRecorder()
		h.ServeHTTP(last, r)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: status = %d, want 429", failThreshold+1, last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Error("expected a Retry-After header once blocked")
	}
}

func TestRateLimitIsPerSource(t *testing.T) {
	srv, _, _ := testServer(t)
	h := srv.Handler()

	bad := httptest.NewRequest(http.MethodGet, "/bounces", nil)
	bad.RemoteAddr = "203.0.113.10:1111"
	bad.Header.Set("Authorization", "Bearer wrong-token")
	for i := 0; i < failThreshold+1; i++ {
		h.ServeHTTP(httptest.NewRecorder(), bad)
	}

	good := httptest.NewRequest(http.MethodGet, "/bounces", nil)
	good.RemoteAddr = "203.0.113.11:2222"
	good.Header.Set("Authorization", "Bearer "+readToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, good)
	if rec.Code != http.StatusOK {
		t.Fatalf("a different source was blocked by another source's failures: status = %d", rec.Code)
	}
}

func TestDashboardConvenienceStatusRejectedByAPI(t *testing.T) {
	srv, _, _ := testServer(t)
	rec := doReq(srv.Handler(), http.MethodGet, "/messages?status=active", readToken)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (active is a dashboard-only convenience, not a documented API value)", rec.Code)
	}
}

// enqueueTestMessage puts one message in both the spool and the history
// store, as the listener does, so requeue/delete tests exercise both layers
// together rather than one in isolation.
func enqueueTestMessage(t *testing.T, st *store.Store, sp *spool.Spool, route string) string {
	t.Helper()
	id, err := sp.Enqueue(spool.Envelope{
		From: "a@example.at", To: []string{"b@example.net"}, Route: route, Received: time.Now().UTC(),
	}, strings.NewReader("Subject: x\r\n\r\nbody\r\n"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	recipients, _ := json.Marshal([]string{"b@example.net"})
	if err := st.RecordMessage(id.String(), "client", route, "a@example.at", "", string(recipients),
		"Test", "smtp", "10.0.0.1", time.Now(), time.Now().Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}
	return id.String()
}
