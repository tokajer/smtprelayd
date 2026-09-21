// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package store

import (
	"testing"
	"time"
)

// Two attempts in the same second must still read back in the order they
// happened. at_time has second precision, which is why backfillSummaries
// orders on the row id rather than on it -- and why the record methods take
// their instant from Store.now: with the wall clock hardwired there is no way
// to place two rows at known instants and assert what the summary columns say
// about them.
func TestAttemptSummaryReflectsTheLatestAttemptWithinOneSecond(t *testing.T) {
	s := testStore(t)

	at := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	s.setClock(func() time.Time { return at })

	if err := s.RecordMessage(MessageRecord{
		QueueID: "CLOCKORDERAAAAAA", Client: "printers", Route: "m365",
		EnvelopeFrom: "device@example.at", Recipients: `["ops@example.at"]`,
		Listener: "submission", RemoteAddr: "192.0.2.10",
		ReceivedAt: at, ExpiresAt: at.Add(96 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// Both inside the same second, so nothing but the insertion order
	// distinguishes them.
	if err := s.RecordAttempt("CLOCKORDERAAAAAA", 1, 451, "try later", "temporary", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAttempt("CLOCKORDERAAAAAA", 2, 250, "accepted", "delivered", nil); err != nil {
		t.Fatal(err)
	}

	msg, err := s.FindMessageByID("CLOCKORDERAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		t.Fatal("message not found")
	}
	if msg.AttemptCount != 2 {
		t.Errorf("attempt_count = %d, want 2", msg.AttemptCount)
	}
	if msg.Status != "delivered" {
		t.Errorf("status = %q, want delivered: the later attempt in the same second decides it", msg.Status)
	}
}
