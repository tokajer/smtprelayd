// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package housekeeping

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// TestReportQuotaLogsOnlyOnTransition drives reportQuota through a rising
// edge, staying over, a falling edge, and staying under, asserting a log
// line is emitted only on the two transitions -- the entire point of the
// edge-trigger. It also covers the division guard with a zero quota.
func TestReportQuotaLogsOnlyOnTransition(t *testing.T) {
	var buf bytes.Buffer
	h := &Housekeeper{log: slog.New(slog.NewTextHandler(&buf, nil))}

	h.reportQuota(900, 1000, true)
	if out := buf.String(); !strings.Contains(out, "spool is filling up") {
		t.Fatalf("rising edge: want log containing %q, got %q", "spool is filling up", out)
	}
	if out := buf.String(); !strings.Contains(out, "percent=90") {
		t.Fatalf("rising edge: want percent=90, got %q", out)
	}

	buf.Reset()
	h.reportQuota(950, 1000, true)
	if out := buf.String(); out != "" {
		t.Fatalf("still over: want no log, got %q", out)
	}

	buf.Reset()
	h.reportQuota(700, 1000, false)
	if out := buf.String(); !strings.Contains(out, "spool is back below the quota warning threshold") {
		t.Fatalf("falling edge: want log containing %q, got %q", "spool is back below the quota warning threshold", out)
	}

	buf.Reset()
	h.reportQuota(600, 1000, false)
	if out := buf.String(); out != "" {
		t.Fatalf("still under: want no log, got %q", out)
	}

	// Fresh housekeeper so quotaWarned starts false and the rising edge
	// fires, reaching the used*100/quota computation with quota == 0.
	zero := &Housekeeper{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	zero.reportQuota(0, 0, true)
}

// claimOne enqueues a message with a short lifetime and claims it, returning
// the leased Meta Fail needs.
func claimOne(t *testing.T, sp *spool.Spool) *spool.Meta {
	t.Helper()
	env := spool.Envelope{From: "a@example.at", To: []string{"b@example.net"}, Origin: "c", Route: "r", Received: time.Now()}
	id, err := sp.Enqueue(env, strings.NewReader("Subject: x\r\n\r\nbody\r\n"), 0, time.Minute)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	for _, m := range sp.ClaimBatch(time.Now().Add(time.Second), 10, nil) {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("ClaimBatch did not return %q", id)
	return nil
}

// TestPassSweepsFailedAndHistoryAndThrottles drives pass end to end against a
// real spool and store: a permanently failed message must disappear from
// both spool/failed and the history store once their retention has passed,
// and sweepFailed's own hourly throttle must hold a second failure back
// rather than sweeping it on every pass.
func TestPassSweepsFailedAndHistoryAndThrottles(t *testing.T) {
	sp, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatalf("spool.Open: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "history.db"), slog.New(slog.NewTextHandler(io.Discard, nil)), 1, true)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	m1 := claimOne(t, sp)
	if err := sp.Fail(m1, "test"); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	sp.SetFailedRetention(time.Hour)
	if err := st.RecordMessage(store.MessageRecord{
		QueueID: m1.ID, Origin: "c", Route: "r", EnvelopeFrom: "a@example.at",
		Recipients: []string{"b@example.net"}, ReceivedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("RecordMessage: %v", err)
	}

	h := New(sp, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	baseNow := time.Now()
	h.pass(context.Background(), baseNow.Add(72*time.Hour))

	if sp.Has(m1.ID) {
		t.Error("failed message still has spool files after the retention sweep")
	}
	msg, err := st.FindMessageByID(m1.ID)
	if err != nil {
		t.Fatalf("FindMessageByID: %v", err)
	}
	if msg != nil {
		t.Error("history row still present after the retention sweep")
	}

	// A second failure, one minute later: sweepFailed must not run again so
	// soon, even though the entry's own age would otherwise make it eligible.
	m2 := claimOne(t, sp)
	if err := sp.Fail(m2, "test"); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	h.pass(context.Background(), baseNow.Add(72*time.Hour+time.Minute))

	if !sp.Has(m2.ID) {
		t.Error("second failure was swept before the hourly throttle allowed it")
	}
}
