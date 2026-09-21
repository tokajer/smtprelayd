// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package delivery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/bounce"
	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/delivery/smarthost"
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testRegistry seeds a registry with the routes and canaries of cfg, the way
// serve() does.
func testRegistry(cfg *config.Config, sp *spool.Spool) *metrics.Registry {
	var routes, canaries []string
	for _, r := range cfg.Routes {
		routes = append(routes, r.Name)
	}
	for _, c := range cfg.Canaries {
		canaries = append(canaries, c.Name)
	}
	return metrics.New(metrics.ConfigExpiry(cfg), sp, routes, canaries, nil)
}

// testManager builds a manager with the collaborators serve() would give
// it, and hands back the ones a test asserts on. They are returned rather
// than read off the manager afterwards: a test that reaches into m.fails and
// type-asserts it back to a *bounce.Notifier is pinned to how the manager
// stores its dependency, not to what it does with it.
func testManager(t *testing.T) (*Manager, *spool.Spool, *bounce.Notifier, *metrics.Registry) {
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
	reg := testRegistry(cfg, sp)
	notifier := bounce.New(cfg, sp, st, discardLog())
	m, err := New(cfg, sp, discardLog(), st, reg, notifier)
	if err != nil {
		t.Fatal(err)
	}
	return m, sp, notifier, reg
}

// TestFailRecordsRealClientFailureButNotANotificationsOwn is the regression
// test for bounce-notification loop prevention: fail() must call
// notifier.RecordFail for an ordinary client message, since that is a real
// bounce worth telling someone about, but must not call it again for a
// notification message's own delivery failure, which is exactly how a
// notification loop would start.
func TestFailRecordsRealClientFailureButNotANotificationsOwn(t *testing.T) {
	m, sp, notifier, _ := testManager(t)

	env := spool.Envelope{From: "a@example.at", To: []string{"b@example.net"}, Route: "m365", Client: "printers", Received: time.Now()}
	if _, err := sp.Enqueue(env, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	meta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("claim failed")
	}
	m.fail(meta, "smarthost rejected it")

	if got := notifier.Pending(); got != 1 {
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

	if got := notifier.Pending(); got != 1 {
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
	m, sp, notifier, _ := testManager(t)

	env := spool.Envelope{From: "canary@example.at", To: []string{"ops@example.at"}, Route: "m365", Client: "smtprelayd-canary", Received: time.Now(), Canary: true}
	if _, err := sp.Enqueue(env, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	meta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("claim failed")
	}
	m.fail(meta, "smarthost rejected the canary")

	if got := notifier.Pending(); got != 1 {
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
	m, _, _, _ := testManager(t)
	if err := m.VerifyTokens(context.Background()); err != nil {
		t.Fatalf("VerifyTokens: %v", err)
	}
}

func TestVerifyTokensPassesWhenEveryRouteTokenFetchSucceeds(t *testing.T) {
	m, _, _, _ := testManager(t)
	m.tokens["m365"] = fakeTokenSource{}
	if err := m.VerifyTokens(context.Background()); err != nil {
		t.Fatalf("VerifyTokens: %v", err)
	}
}

func TestVerifyTokensFailsStartupOnRejectedCredential(t *testing.T) {
	m, _, _, _ := testManager(t)
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

// backoff, isPermanent, isAuthFailure and extractSMTPError are pure and were
// all at 0% coverage, yet between them they decide whether a message is
// retried or given up on. isPermanent answering wrong in one direction empties
// the whole queue into spool/failed -- which is precisely the reasoning the
// comment above attempt's 535 handling gives for not classifying an
// authentication failure as permanent.

// docs/guides/CONFIGURATION.md documents the schedule as "minutes between
// attempts, then the last interval repeats". Both ends are clamped: attempt
// numbering starts at 1, and nothing past the end of the schedule may index
// out of it.
func TestBackoffFollowsTheScheduleAndRepeatsTheLast(t *testing.T) {
	m := &Manager{cfg: &config.Config{
		Queue: config.Queue{RetryScheduleMin: []int{1, 5, 15, 30, 60, 120}},
	}}
	for _, tc := range []struct {
		attempt int
		want    time.Duration
	}{
		{0, 1 * time.Minute},  // clamped up: there is no attempt zero
		{-3, 1 * time.Minute}, // and nothing below it either
		{1, 1 * time.Minute},
		{2, 5 * time.Minute},
		{6, 120 * time.Minute}, // the last entry
		{7, 120 * time.Minute}, // and it repeats from here on
		{999, 120 * time.Minute},
	} {
		if got := m.backoff(tc.attempt); got != tc.want {
			t.Errorf("backoff(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

// A single-entry schedule is the edge the clamp is really protecting: every
// index resolves to the same element, and none may fall outside it.
func TestBackoffWithASingleEntrySchedule(t *testing.T) {
	m := &Manager{cfg: &config.Config{Queue: config.Queue{RetryScheduleMin: []int{7}}}}
	for _, attempt := range []int{0, 1, 2, 50} {
		if got := m.backoff(attempt); got != 7*time.Minute {
			t.Errorf("backoff(%d) = %v, want 7m", attempt, got)
		}
	}
}

// The classifiers must look through wrapping: attempt wraps the smarthost
// error with route context before these ever see it.
func TestFailureClassifiersSeeThroughWrapping(t *testing.T) {
	perm := &smarthost.PermError{Err: errors.New("550 mailbox unavailable")}
	temp := &smarthost.TempError{Err: errors.New("451 try later")}
	auth := &smarthost.AuthError{Err: errors.New("535 rejected")}

	for _, tc := range []struct {
		name               string
		err                error
		permanent, badAuth bool
	}{
		{"permanent", perm, true, false},
		{"permanent, wrapped", fmt.Errorf("route r: %w", perm), true, false},
		{"temporary", temp, false, false},
		{"temporary, wrapped", fmt.Errorf("route r: %w", temp), false, false},
		// An authentication failure is the relay's problem, never the
		// message's: it must be neither permanent nor silently temporary.
		{"authentication", auth, false, true},
		{"authentication, wrapped", fmt.Errorf("route r: %w", auth), false, true},
		{"plain error", errors.New("connection reset"), false, false},
	} {
		if got := isPermanent(tc.err); got != tc.permanent {
			t.Errorf("%s: isPermanent = %v, want %v", tc.name, got, tc.permanent)
		}
		if got := isAuthFailure(tc.err); got != tc.badAuth {
			t.Errorf("%s: isAuthFailure = %v, want %v", tc.name, got, tc.badAuth)
		}
	}
}

func TestExtractSMTPError(t *testing.T) {
	te := &textproto.Error{Code: 550, Msg: "mailbox unavailable"}
	if code, msg := extractSMTPError(te); code != 550 || msg != "mailbox unavailable" {
		t.Errorf("extractSMTPError(textproto) = %d, %q; want 550, \"mailbox unavailable\"", code, msg)
	}
	// Still found once attempt has wrapped it in route context.
	if code, _ := extractSMTPError(fmt.Errorf("route r: %w", te)); code != 550 {
		t.Errorf("a wrapped textproto.Error yielded code %d, want 550", code)
	}
	// No SMTP code in sight: the contract is code 0 and the error's own text,
	// which is what the attempt record then stores.
	code, msg := extractSMTPError(errors.New("connection reset by peer"))
	if code != 0 || msg != "connection reset by peer" {
		t.Errorf("extractSMTPError(plain) = %d, %q; want 0 and the error text", code, msg)
	}
}

// hold defers a message that hit the route rate limit. Its doc comment makes
// a promise the code has to keep: the message was never offered to the
// smarthost, so pacing must consume neither its retry budget nor its
// lifetime. Break that and a paced message runs out of attempts, or expires,
// for reasons that have nothing to do with the smarthost.
func TestHoldDoesNotConsumeTheRetryBudget(t *testing.T) {
	m, sp, _, _ := testManager(t)
	env := spool.Envelope{From: "a@example.at", To: []string{"b@example.net"},
		Route: "m365", Client: "printers", Received: time.Now()}
	if _, err := sp.Enqueue(env, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	meta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("claim failed")
	}
	attemptsBefore, expiresBefore := meta.Attempts, meta.Expires

	m.hold(meta, 5*time.Minute)

	if meta.Attempts != attemptsBefore {
		t.Errorf("hold moved the attempt counter from %d to %d; pacing must not spend a retry",
			attemptsBefore, meta.Attempts)
	}
	if !meta.Expires.Equal(expiresBefore) {
		t.Errorf("hold moved the expiry from %v to %v", expiresBefore, meta.Expires)
	}
	if want := time.Now().Add(5 * time.Minute); meta.NextAttempt.Sub(want) > time.Minute || want.Sub(meta.NextAttempt) > time.Minute {
		t.Errorf("next attempt at %v, want about %v", meta.NextAttempt, want)
	}
	// The deferral has to reach the spool, not only the caller's copy: hold
	// no longer writes metadata, so the queue is the only place the new
	// attempt time exists.
	if _, ok := sp.Claim(time.Now()); ok {
		t.Error("a held message was handed straight back out")
	}
	if _, ok := sp.Claim(time.Now().Add(6 * time.Minute)); !ok {
		t.Error("a held message never became due again")
	}
}

// The deferral is capped at the message's own expiry: pushing it past that
// would leave a message that can never be tried again yet is not expired
// either, so nothing would ever clear it.
func TestHoldNeverDefersPastExpiry(t *testing.T) {
	m, sp, _, _ := testManager(t)
	env := spool.Envelope{From: "a@example.at", To: []string{"b@example.net"},
		Route: "m365", Client: "printers", Received: time.Now()}
	if _, err := sp.Enqueue(env, strings.NewReader("x"), 0, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	meta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("claim failed")
	}

	m.hold(meta, time.Hour)

	if meta.NextAttempt.After(meta.Expires) {
		t.Errorf("next attempt %v is past the expiry %v", meta.NextAttempt, meta.Expires)
	}
	if !meta.NextAttempt.Equal(meta.Expires) {
		t.Errorf("next attempt %v, want it pinned to the expiry %v", meta.NextAttempt, meta.Expires)
	}
}
