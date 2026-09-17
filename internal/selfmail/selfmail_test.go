// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package selfmail

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

func testDeps(t *testing.T) (*spool.Spool, *store.Store, *slog.Logger) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sp, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir(), log, 90, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return sp, st, log
}

func spooled(t *testing.T, sp *spool.Spool) (*spool.Meta, string) {
	t.Helper()
	meta, ok := sp.Claim(time.Now().Add(time.Minute))
	if !ok {
		t.Fatal("nothing was spooled")
	}
	f, err := sp.Open(meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return meta, string(raw)
}

// The distinction that matters, and the one this package got wrong once: a
// notification carries a readable From header so a person can see who sent
// it, while its reverse path stays empty so that failing to deliver it
// cannot produce another notification.
func TestHeaderFromAndEnvelopeFromAreIndependent(t *testing.T) {
	sp, st, log := testDeps(t)
	_, err := Enqueue(sp, st, log, Message{
		HeaderFrom:   "postmaster@example.at",
		EnvelopeFrom: "",
		To:           []string{"ops@example.at"},
		Subject:      "digest",
		Body:         "two failures\r\n",
		Client:       "expiry-watch",
		Route:        "m365",
		Listener:     "bounce-notifier",
		Notification: true,
	}, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	meta, body := spooled(t, sp)
	if meta.Envelope.From != "" {
		t.Errorf("envelope sender = %q, want the null reverse path", meta.Envelope.From)
	}
	if !strings.Contains(body, "From: postmaster@example.at\r\n") {
		t.Errorf("From header missing or wrong:\n%s", body)
	}
	if !meta.Envelope.Notification {
		t.Error("Notification must reach the envelope")
	}
	if meta.Envelope.Canary {
		t.Error("Canary must not be set for a notification")
	}
}

// A canary is ordinary mail with a real sender on both sides, and must not
// be flagged as a notification: its failure is exactly what should reach the
// bounce digest.
func TestCanaryKeepsARealSenderAndIsNotANotification(t *testing.T) {
	sp, st, log := testDeps(t)
	_, err := Enqueue(sp, st, log, Message{
		HeaderFrom:   "canary@example.at",
		EnvelopeFrom: "canary@example.at",
		To:           []string{"probe@example.at"},
		Subject:      "canary",
		Body:         "probe\r\n",
		Client:       "m365-daily",
		Route:        "m365",
		Listener:     "canary",
		Canary:       true,
	}, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	meta, body := spooled(t, sp)
	if meta.Envelope.From != "canary@example.at" {
		t.Errorf("envelope sender = %q, want the canary's own", meta.Envelope.From)
	}
	if meta.Envelope.Notification {
		t.Error("a canary flagged as a notification would be excluded from the bounce digest it exists to feed")
	}
	if !meta.Envelope.Canary {
		t.Error("Canary must reach the envelope")
	}
	if !strings.Contains(body, "From: canary@example.at\r\n") {
		t.Errorf("From header missing:\n%s", body)
	}
}

// The header block has to terminate before the body, or the body is parsed
// as more headers by everything downstream.
func TestHeaderBlockIsTerminatedAndComplete(t *testing.T) {
	sp, st, log := testDeps(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if _, err := Enqueue(sp, st, log, Message{
		HeaderFrom: "a@example.at", EnvelopeFrom: "a@example.at",
		To: []string{"b@example.at", "c@example.at"}, Subject: "s", Body: "the body\r\n",
		Client: "x", Route: "r", Listener: "l",
	}, time.Hour, now); err != nil {
		t.Fatal(err)
	}

	_, body := spooled(t, sp)
	head, rest, found := strings.Cut(body, "\r\n\r\n")
	if !found {
		t.Fatalf("no blank line terminating the header block:\n%s", body)
	}
	if rest != "the body\r\n" {
		t.Errorf("body = %q, want it after the blank line", rest)
	}
	for _, want := range []string{
		"From: a@example.at",
		"To: b@example.at, c@example.at",
		"Subject: s",
		"Date: Mon, 01 Jun 2026 12:00:00 +0000",
		"Content-Type: " + ContentType,
	} {
		if !strings.Contains(head, want) {
			t.Errorf("header block is missing %q:\n%s", want, head)
		}
	}
}

// The journal record has to describe what was actually spooled, since the
// dashboard reads it rather than the message.
func TestJournalRecordsWhatWasSpooled(t *testing.T) {
	sp, st, log := testDeps(t)
	id, err := Enqueue(sp, st, log, Message{
		HeaderFrom: "a@example.at", EnvelopeFrom: "a@example.at",
		To: []string{"b@example.at"}, Subject: "recorded", Body: "x\r\n",
		Client: "canary-1", Route: "m365", Listener: "canary", Canary: true,
	}, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	m, err := st.FindMessageByID(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("the message was not recorded in the journal")
	}
	if m.Client != "canary-1" || m.Route != "m365" || m.Listener != "canary" {
		t.Errorf("journal row = client %q route %q listener %q", m.Client, m.Route, m.Listener)
	}
	if m.Subject != "recorded" {
		t.Errorf("Subject = %q", m.Subject)
	}
	if m.ContentType != ContentType {
		t.Errorf("ContentType = %q, want %q", m.ContentType, ContentType)
	}
	if m.SizeBytes == 0 {
		t.Error("SizeBytes was not recorded")
	}
	// Five headers were written; a zero would mean the block was not parsed.
	if m.HeaderCount != 5 {
		t.Errorf("HeaderCount = %d, want 5", m.HeaderCount)
	}
}
