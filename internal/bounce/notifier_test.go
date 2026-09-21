// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package bounce

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
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

func testNotifier(t *testing.T, cfg *config.Config) (*Notifier, *spool.Spool, *store.Store) {
	t.Helper()
	sp, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The store is opened with the same retain_subjects the configuration
	// carries, which is how cmd/smtprelayd wires the two. Hardcoding true
	// here while a test flipped only the config field meant the two halves
	// disagreed in a way the service cannot reach -- and the digest's
	// redaction test was then checking a second copy of the policy in this
	// package rather than the store's own, which is the one that runs.
	st, err := store.Open(t.TempDir(), discardLog(), 90, cfg.History.RetainSubjects)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(cfg, sp, st, discardLog()), sp, st
}

func baseCfg() *config.Config {
	return &config.Config{
		Queue:   config.Queue{MaxLifetimeHours: 96},
		History: config.History{RetainSubjects: true},
		Bounce: config.Bounce{
			Sender: "bounce@example.at", NotifyRoute: "m365",
			DigestMinutes: 15, MaxPerHour: 2,
			Notify: []string{"ops@example.at"},
		},
		Clients: []config.Client{
			{Name: "printers", Route: "m365"},
			{Name: "erp", Route: "m365", Bounce: config.Bounce{Notify: []string{"erp-admins@example.at"}}},
		},
	}
}

// recordFailed puts a permanently-failed message in the store, as
// delivery.Manager.fail would have via store.RecordAttempt before calling
// RecordFail.
func recordFailed(t *testing.T, st *store.Store, id, client string) {
	t.Helper()
	recipients, _ := json.Marshal([]string{"someone@partner.example"})
	now := time.Now()
	if err := st.RecordMessage(store.MessageRecord{QueueID: id, Client: client, Route: "m365", EnvelopeFrom: "relay@example.at", OriginalFrom: "orig@local", Recipients: string(recipients), Subject: "Scan job", Listener: "smtp", RemoteAddr: "10.0.0.1", ReceivedAt: now, ExpiresAt: now.Add(96 * time.Hour), TLSUsed: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordAttempt(id, 1, 550, "5.1.1 User unknown", "permanent", nil); err != nil {
		t.Fatal(err)
	}
}

func TestRecipientsForPrefersClientOverride(t *testing.T) {
	n, _, _ := testNotifier(t, baseCfg())
	if got := n.recipientsFor("erp"); len(got) != 1 || got[0] != "erp-admins@example.at" {
		t.Fatalf("got %v, want the client override", got)
	}
	if got := n.recipientsFor("printers"); len(got) != 1 || got[0] != "ops@example.at" {
		t.Fatalf("got %v, want the global list", got)
	}
	if got := n.recipientsFor("unknown-client"); len(got) != 1 || got[0] != "ops@example.at" {
		t.Fatalf("got %v, want the global fallback for an unconfigured client", got)
	}
}

func TestRecipientsForEmptyWhenBothUnset(t *testing.T) {
	cfg := baseCfg()
	cfg.Bounce.Notify = nil
	cfg.Clients[0].Bounce.Notify = nil
	n, _, _ := testNotifier(t, cfg)
	if got := n.recipientsFor("printers"); len(got) != 0 {
		t.Fatalf("got %v, want no recipients", got)
	}
}

func TestDispatchComposesDigestWithLoopPreventionProperties(t *testing.T) {
	cfg := baseCfg()
	n, sp, st := testNotifier(t, cfg)

	recordFailed(t, st, "FAILEDMSGAAAAAAA", "printers")
	n.RecordFail("printers", "FAILEDMSGAAAAAAA")

	n.dispatch(time.Now())

	if sp.Len() != 1 {
		t.Fatalf("spool has %d messages, want 1 digest enqueued", sp.Len())
	}
	meta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("digest message not claimable")
	}
	if meta.Envelope.From != "" {
		t.Errorf("envelope sender = %q, want empty (null reverse path)", meta.Envelope.From)
	}
	if !meta.Envelope.Notification {
		t.Error("digest message not flagged as a notification")
	}
	if len(meta.Envelope.To) != 1 || meta.Envelope.To[0] != "ops@example.at" {
		t.Errorf("recipients = %v", meta.Envelope.To)
	}
	if meta.Envelope.Route != "m365" {
		t.Errorf("route = %q, want the configured notify_route", meta.Envelope.Route)
	}

	f, err := sp.OpenBody(meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(f)
	f.Close()
	text := string(body)
	if !strings.Contains(text, "FAILEDMSGAAAAAAA") {
		t.Errorf("digest body missing the failed queue ID:\n%s", text)
	}
	if !strings.Contains(text, "Scan job") {
		t.Errorf("digest body missing the failed message's subject:\n%s", text)
	}
	if !strings.Contains(text, "5.1.1 User unknown") {
		t.Errorf("digest body missing the SMTP response:\n%s", text)
	}
	if !strings.HasPrefix(text, "From: bounce@example.at\r\n") {
		t.Errorf("digest header From missing or wrong:\n%s", text)
	}
}

func TestDispatchRedactsSubjectWhenRetentionDisabled(t *testing.T) {
	cfg := baseCfg()
	cfg.History.RetainSubjects = false
	n, sp, st := testNotifier(t, cfg)

	recordFailed(t, st, "REDACTINDIGESTAB", "printers")
	n.RecordFail("printers", "REDACTINDIGESTAB")
	n.dispatch(time.Now())

	meta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("digest not claimable")
	}
	f, err := sp.OpenBody(meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(f)
	f.Close()
	if strings.Contains(string(body), "Scan job") {
		t.Fatalf("subject leaked into the digest despite retain_subjects=false:\n%s", body)
	}
	if !strings.Contains(string(body), "[redacted]") {
		t.Fatalf("expected [redacted] marker:\n%s", body)
	}
}

func TestDispatchSkipsClientWithNoRecipients(t *testing.T) {
	cfg := baseCfg()
	cfg.Bounce.Notify = nil // global list empty, "printers" has no override
	n, sp, st := testNotifier(t, cfg)

	recordFailed(t, st, "NOONETOTELLABC1", "printers")
	n.RecordFail("printers", "NOONETOTELLABC1")
	n.dispatch(time.Now())

	if sp.Len() != 0 {
		t.Fatalf("a digest was enqueued despite no configured recipients: %d messages", sp.Len())
	}
}

func TestVolumeCapSuppressesAndCarriesOver(t *testing.T) {
	cfg := baseCfg()
	cfg.Bounce.MaxPerHour = 1
	n, sp, st := testNotifier(t, cfg)

	recordFailed(t, st, "OVERCAPMSGAAAAA1", "printers")
	recordFailed(t, st, "OVERCAPMSGAAAAA2", "erp")
	n.RecordFail("printers", "OVERCAPMSGAAAAA1")
	n.RecordFail("erp", "OVERCAPMSGAAAAA2")

	now := time.Now()
	n.dispatch(now)

	if sp.Len() != 1 {
		t.Fatalf("spool has %d messages, want exactly 1 (the cap is 1/hour)", sp.Len())
	}

	// The suppressed client's failure must not be lost: it is carried into
	// the next hour's digest rather than dropped.
	n.mu.Lock()
	carried := len(n.pending["erp"]) + len(n.pending["printers"])
	n.mu.Unlock()
	if carried != 1 {
		t.Fatalf("got %d carried-over failures, want 1", carried)
	}

	// Advance past the hour boundary and dispatch again: the cap resets and
	// the carried-over failure is sent.
	n.dispatch(now.Add(time.Hour + time.Minute))
	if sp.Len() != 2 {
		t.Fatalf("spool has %d messages after the cap reset, want 2", sp.Len())
	}
}

func TestRunReturnsImmediatelyWhenDigestMinutesIsZero(t *testing.T) {
	cfg := baseCfg()
	cfg.Bounce.DigestMinutes = 0
	n, _, _ := testNotifier(t, cfg)

	done := make(chan struct{})
	go func() {
		n.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return immediately for a zero digest interval")
	}
}

func TestRunStopsOnContextCancellation(t *testing.T) {
	n, _, _ := testNotifier(t, baseCfg())
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		n.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}
}

// Notify is the channel anything with news for the operator reuses, so it
// must carry the same loop-prevention properties a digest does: without the
// null reverse path and the Notification flag, a warning that failed to
// deliver would generate a bounce, which would generate another warning.
func TestNotifyEnqueuesWithLoopPrevention(t *testing.T) {
	n, sp, _ := testNotifier(t, baseCfg())
	now := time.Now()

	if err := n.Notify("expiry-watch", "[smtprelayd] something expires", "body text", now); err != nil {
		t.Fatal(err)
	}

	meta, ok := sp.Claim(time.Now().Add(time.Minute))
	if !ok {
		t.Fatal("Notify queued nothing")
	}
	if meta.Envelope.From != "" {
		t.Errorf("envelope sender = %q, want the null reverse path", meta.Envelope.From)
	}
	if !meta.Envelope.Notification {
		t.Error("Notification must be set, or the delivery manager treats its own failure as a new bounce")
	}
	if meta.Envelope.Route != "m365" {
		t.Errorf("route = %q, want bounce.notify_route", meta.Envelope.Route)
	}
	if len(meta.Envelope.To) != 1 || meta.Envelope.To[0] != "ops@example.at" {
		t.Errorf("recipients = %v, want the global bounce.notify", meta.Envelope.To)
	}

	f, err := sp.OpenBody(meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		"From: bounce@example.at\r\n",
		"To: ops@example.at\r\n",
		"Subject: [smtprelayd] something expires\r\n",
		"\r\n\r\nbody text",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("message is missing %q:\n%s", want, body)
		}
	}
}

// No contact configured is how notifications are switched off, and must be a
// quiet no-op rather than an error the caller has to special-case.
func TestNotifyWithoutRecipientsSendsNothing(t *testing.T) {
	cfg := baseCfg()
	cfg.Bounce.Notify = nil
	n, sp, _ := testNotifier(t, cfg)

	if err := n.Notify("expiry-watch", "subject", "body", time.Now()); err != nil {
		t.Fatalf("Notify with no recipients should be a no-op, got %v", err)
	}
	if _, ok := sp.Claim(time.Now()); ok {
		t.Error("Notify queued a message with nowhere to send it")
	}
}

// A digest must keep working unchanged now that it shares enqueue with
// Notify: the header block is the part that moved.
func TestDigestStillRendersItsHeaderBlock(t *testing.T) {
	n, sp, st := testNotifier(t, baseCfg())
	now := time.Now()
	recordFailed(t, st, "0000000000000000000000000000000a", "printers")
	n.RecordFail("printers", "0000000000000000000000000000000a")
	n.dispatch(now)

	meta, ok := sp.Claim(time.Now().Add(time.Minute))
	if !ok {
		t.Fatal("dispatch queued nothing")
	}
	f, err := sp.OpenBody(meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, _ := io.ReadAll(f)
	body := string(raw)
	if !strings.HasPrefix(body, "From: bounce@example.at\r\nTo: ops@example.at\r\n") {
		t.Errorf("digest header block is wrong:\n%s", body)
	}
	if !strings.Contains(body, "could not be delivered") {
		t.Errorf("digest body is missing:\n%s", body)
	}
}

// bounce.max_per_hour caps how many digests go out, never how long one is,
// and the length follows the outage: measured at roughly 167 bytes per entry,
// 10 000 failures produced a 1.59 MB message and 10 000 history lookups. A
// mail that size is unreadable and is what a smarthost refuses, so the
// notification would have failed at the one moment it exists for.
func TestDigestListsAtMostMaxEntriesAndSaysHowManyItLeftOut(t *testing.T) {
	dir := t.TempDir()
	sp, err := spool.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir(), discardLog(), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := baseCfg()
	n := New(cfg, sp, st, discardLog())

	const failures = maxDigestEntries + 37
	for i := 0; i < failures; i++ {
		id := fmt.Sprintf("QCAP%022d", i)
		recordFailed(t, st, id, "printers")
		n.RecordFail("printers", id)
	}

	n.dispatch(time.Now())

	body := onlyQueuedBody(t, dir)
	if got := strings.Count(body, "Queue ID:   QCAP"); got != maxDigestEntries {
		t.Errorf("digest lists %d entries, want %d", got, maxDigestEntries)
	}
	// The count in the opening line stays the true one: the cap changes how
	// much is listed, never what is reported as having failed.
	if !strings.Contains(body, fmt.Sprintf("%d message(s)", failures)) {
		t.Errorf("digest does not report the real failure count of %d", failures)
	}
	// And the reader has to be told the list is short, or a truncated digest
	// reads as a complete one.
	if !strings.Contains(body, fmt.Sprintf("and %d more", failures-maxDigestEntries)) {
		t.Errorf("digest does not say how many it left out:\n%s", tail(body))
	}
}

// Below the cap nothing changes: no truncation, no closing note that would
// read as a warning where there is nothing to warn about.
func TestDigestUnderTheCapListsEverythingAndSaysNothingExtra(t *testing.T) {
	dir := t.TempDir()
	sp, err := spool.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir(), discardLog(), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	n := New(baseCfg(), sp, st, discardLog())
	const failures = 3
	for i := 0; i < failures; i++ {
		id := fmt.Sprintf("QSML%022d", i)
		recordFailed(t, st, id, "printers")
		n.RecordFail("printers", id)
	}

	n.dispatch(time.Now())

	body := onlyQueuedBody(t, dir)
	if got := strings.Count(body, "Queue ID:   QSML"); got != failures {
		t.Errorf("digest lists %d entries, want all %d", got, failures)
	}
	if strings.Contains(body, "more, not listed here") {
		t.Error("a digest under the cap claims it left something out")
	}
}

// onlyQueuedBody returns the single message the notifier spooled.
func onlyQueuedBody(t *testing.T, spoolDir string) string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(spoolDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(p) == ".eml" {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one queued message, found %d", len(found))
	}
	b, err := os.ReadFile(found[0])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func tail(s string) string {
	if len(s) > 400 {
		return "..." + s[len(s)-400:]
	}
	return s
}

// bounce.max_per_hour suppresses sending, not recording, so nothing drains
// the pending map while the cap holds. The IDs past maxPendingPerClient are
// therefore counted rather than kept: the digest lists at most
// maxDigestEntries of them anyway, and every failure is a history row.
func TestPendingIsBoundedPerClient(t *testing.T) {
	n := New(&config.Config{}, nil, nil, discardLog())
	const recorded = maxPendingPerClient + 500
	for i := 0; i < recorded; i++ {
		n.RecordFail("printers", fmt.Sprintf("Q%015d", i))
	}

	n.mu.Lock()
	kept := len(n.pending["printers"])
	overflow := n.overflow["printers"]
	n.mu.Unlock()

	if kept != maxPendingPerClient {
		t.Fatalf("kept %d queue IDs, want the cap of %d", kept, maxPendingPerClient)
	}
	if overflow != recorded-maxPendingPerClient {
		t.Fatalf("overflow counted %d, want %d", overflow, recorded-maxPendingPerClient)
	}
	// The reported total is still the true one: a digest that undercounts
	// what failed is worse than one that lists fewer of them.
	if got := n.Pending(); got != recorded {
		t.Fatalf("Pending() = %d, want %d", got, recorded)
	}
}
