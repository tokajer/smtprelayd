// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package delivery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/delivery/smarthost"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testManager(t *testing.T) (*Manager, *spool.Spool) {
	t.Helper()
	cfg := &config.Config{
		Queue: config.Queue{MaxLifetimeHours: 96, RetryScheduleMin: []int{1}},
		Bounce: config.Bounce{
			Sender: "bounce@example.at", NotifyRoute: "m365",
			DigestMinutes: 15, MaxPerHour: 10, Notify: []string{"ops@example.at"},
		},
		Routes: []config.Route{{Name: "m365", Auth: "none", MaxConcurrent: 1}},
	}
	sp, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir(), discardLog(), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	m, err := New(cfg, sp, discardLog(), st)
	if err != nil {
		t.Fatal(err)
	}
	return m, sp
}

// TestFailRecordsRealClientFailureButNotANotificationsOwn is the regression
// test for bounce-notification loop prevention: fail() must call
// notifier.RecordFail for an ordinary client message, since that is a real
// bounce worth telling someone about, but must not call it again for a
// notification message's own delivery failure, which is exactly how a
// notification loop would start.
func TestFailRecordsRealClientFailureButNotANotificationsOwn(t *testing.T) {
	m, sp := testManager(t)

	env := spool.Envelope{From: "a@example.at", To: []string{"b@example.net"}, Route: "m365", Client: "printers", Received: time.Now()}
	if _, err := sp.Enqueue(env, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	meta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("claim failed")
	}
	m.fail(meta, "smarthost rejected it")

	if got := m.Notifier().Pending(); got != 1 {
		t.Fatalf("pending = %d after a real client failure, want 1", got)
	}

	notifEnv := spool.Envelope{From: "", To: []string{"ops@example.at"}, Route: "m365", Client: "printers", Received: time.Now(), Notification: true}
	if _, err := sp.Enqueue(notifEnv, strings.NewReader("y"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	notifMeta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("claim failed")
	}
	m.fail(notifMeta, "notify route unreachable")

	if got := m.Notifier().Pending(); got != 1 {
		t.Fatalf("pending = %d after a notification's own failure, want still 1 (no loop)", got)
	}
}

// TestFailRecordsACanarysOwnFailureUnlikeANotifications is the companion
// regression test to the one above: a canary message must still reach
// RecordFail on failure, unlike a bounce notification, since reporting a
// failed canary through the bounce digest is the entire point of it. Only
// route-level metrics attribution treats Canary like Notification; the
// RecordFail gate in fail() checks Notification alone, deliberately.
func TestFailRecordsACanarysOwnFailureUnlikeANotifications(t *testing.T) {
	m, sp := testManager(t)

	env := spool.Envelope{From: "canary@example.at", To: []string{"ops@example.at"}, Route: "m365", Client: "smtprelayd-canary", Received: time.Now(), Canary: true}
	if _, err := sp.Enqueue(env, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	meta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("claim failed")
	}
	m.fail(meta, "smarthost rejected the canary")

	if got := m.Notifier().Pending(); got != 1 {
		t.Fatalf("pending = %d after a canary's own failure, want 1 (reported like a real failure)", got)
	}
}

// fakeTokenSource stands in for authms365.TokenSource so VerifyTokens can be
// tested without reaching the real login.microsoftonline.com: authms365.New
// hardcodes that authority and has no seam for a test server.
type fakeTokenSource struct{ err error }

func (f fakeTokenSource) Token(context.Context) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return "tok", nil
}

func TestVerifyTokensSkipsRoutesWithNoCachedSource(t *testing.T) {
	// testManager's one route has Auth: "none", so New never populated
	// m.tokens for it; VerifyTokens must not treat that as a failure.
	m, _ := testManager(t)
	if err := m.VerifyTokens(context.Background()); err != nil {
		t.Fatalf("VerifyTokens: %v", err)
	}
}

func TestVerifyTokensPassesWhenEveryRouteTokenFetchSucceeds(t *testing.T) {
	m, _ := testManager(t)
	m.tokens["m365"] = fakeTokenSource{}
	if err := m.VerifyTokens(context.Background()); err != nil {
		t.Fatalf("VerifyTokens: %v", err)
	}
}

func TestVerifyTokensFailsStartupOnRejectedCredential(t *testing.T) {
	m, _ := testManager(t)
	m.tokens["m365"] = fakeTokenSource{err: errors.New("invalid_client")}

	err := m.VerifyTokens(context.Background())
	if err == nil {
		t.Fatal("VerifyTokens accepted a route whose token fetch failed")
	}
	if !strings.Contains(err.Error(), "m365") || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestReportQuotaLogsOnlyOnTransition drives reportQuota through a rising
// edge, staying over, a falling edge, and staying under, asserting a log
// line is emitted only on the two transitions -- the entire point of the
// edge-trigger. It also covers the division guard with a zero quota.
func TestReportQuotaLogsOnlyOnTransition(t *testing.T) {
	var buf bytes.Buffer
	m := &Manager{log: slog.New(slog.NewTextHandler(&buf, nil))}

	m.reportQuota(900, 1000, true)
	if out := buf.String(); !strings.Contains(out, "spool is filling up") {
		t.Fatalf("rising edge: want log containing %q, got %q", "spool is filling up", out)
	}
	if out := buf.String(); !strings.Contains(out, "percent=90") {
		t.Fatalf("rising edge: want percent=90, got %q", out)
	}

	buf.Reset()
	m.reportQuota(950, 1000, true)
	if out := buf.String(); out != "" {
		t.Fatalf("still over: want no log, got %q", out)
	}

	buf.Reset()
	m.reportQuota(700, 1000, false)
	if out := buf.String(); !strings.Contains(out, "spool is back below the quota warning threshold") {
		t.Fatalf("falling edge: want log containing %q, got %q", "spool is back below the quota warning threshold", out)
	}

	buf.Reset()
	m.reportQuota(600, 1000, false)
	if out := buf.String(); out != "" {
		t.Fatalf("still under: want no log, got %q", out)
	}

	// Fresh manager so quotaWarned starts false and the rising edge fires,
	// reaching the used*100/quota computation with quota == 0.
	zero := &Manager{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	zero.reportQuota(0, 0, true)
}

// Compile-time assertion that fakeTokenSource satisfies the interface
// delivery actually stores, so a signature drift there fails this test file
// to build rather than silently type-checking against something else.
var _ smarthost.TokenSource = fakeTokenSource{}
