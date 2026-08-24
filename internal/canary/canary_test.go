// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package canary

import (
	"context"
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

func testRunner(t *testing.T, cfg *config.Config) (*Runner, *spool.Spool, *store.Store) {
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
		Service: config.Service{Hostname: "relay01"},
		Queue:   config.Queue{MaxLifetimeHours: 96},
		History: config.History{RetainSubjects: true},
		Canary: config.Canary{
			Sender: "canary@example.at", Recipient: "ops@example.at",
			Route: "m365", IntervalMinutes: 1440,
		},
	}
}

// TestSendEnqueuesAnOrdinaryNonNotificationCanaryMessage is the central
// contract this package exists for: the envelope must carry Canary: true
// (so route metrics stay clean, see internal/delivery) but Notification
// must stay false (so a failure still reaches the bounce digest, unlike a
// bounce notification's own failure).
func TestSendEnqueuesAnOrdinaryNonNotificationCanaryMessage(t *testing.T) {
	r, sp, _ := testRunner(t, baseCfg())

	if err := r.send(time.Now()); err != nil {
		t.Fatal(err)
	}

	if sp.Len() != 1 {
		t.Fatalf("spool has %d messages, want 1", sp.Len())
	}
	meta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("canary message not claimable")
	}
	if !meta.Envelope.Canary {
		t.Error("envelope not flagged as a canary")
	}
	if meta.Envelope.Notification {
		t.Error("envelope flagged as a notification; a canary must not be, or its failure would never reach the bounce digest")
	}
	if meta.Envelope.From != "canary@example.at" {
		t.Errorf("From = %q, want the configured sender", meta.Envelope.From)
	}
	if len(meta.Envelope.To) != 1 || meta.Envelope.To[0] != "ops@example.at" {
		t.Errorf("To = %v, want the configured recipient", meta.Envelope.To)
	}
	if meta.Envelope.Route != "m365" {
		t.Errorf("Route = %q, want the configured route", meta.Envelope.Route)
	}

	f, err := sp.Open(meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(f)
	f.Close()
	text := string(body)
	if !strings.HasPrefix(text, "From: canary@example.at\r\n") {
		t.Errorf("message header From missing or wrong:\n%s", text)
	}
	if !strings.Contains(text, "relay01") {
		t.Errorf("message body missing the hostname:\n%s", text)
	}
}

func TestSendRecordsHistory(t *testing.T) {
	r, sp, st := testRunner(t, baseCfg())

	if err := r.send(time.Now()); err != nil {
		t.Fatal(err)
	}

	meta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("canary message not claimable")
	}
	msg, err := st.FindMessageByID(meta.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		t.Fatal("canary message not found in history")
	}
	if msg.Client != clientName {
		t.Errorf("history client = %q, want %q", msg.Client, clientName)
	}
}

func TestRunReturnsImmediatelyWhenRecipientIsUnset(t *testing.T) {
	cfg := baseCfg()
	cfg.Canary.Recipient = ""
	r, _, _ := testRunner(t, cfg)

	done := make(chan struct{})
	go func() {
		r.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return immediately with no recipient configured")
	}
}

func TestRunReturnsImmediatelyWhenIntervalIsZero(t *testing.T) {
	cfg := baseCfg()
	cfg.Canary.IntervalMinutes = 0
	r, _, _ := testRunner(t, cfg)

	done := make(chan struct{})
	go func() {
		r.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return immediately for a zero interval")
	}
}

func TestRunStopsOnContextCancellation(t *testing.T) {
	r, _, _ := testRunner(t, baseCfg())
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}
}
