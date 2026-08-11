// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package bounce

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
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
	st, err := store.Open(t.TempDir(), discardLog(), 90, true)
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

	f, err := sp.Open(meta.ID)
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
	f, err := sp.Open(meta.ID)
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
