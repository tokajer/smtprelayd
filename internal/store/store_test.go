// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package store

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	tmpDir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	s, err := Open(tmpDir, log, 90, true)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRecordMessageAndAttempt(t *testing.T) {
	s := testStore(t)

	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	err := s.RecordMessage(
		"TESTQUEUEID1",
		"printer-client",
		"m365",
		"relay@example.com",
		"printer@local",
		string(recipients),
		"Test Subject",
		"smtp",
		"10.0.0.5",
		now,
		expires,
		true,
	)
	if err != nil {
		t.Fatalf("RecordMessage failed: %v", err)
	}

	// Record an attempt.
	err = s.RecordAttempt("TESTQUEUEID1", 1, 550, "5.1.1 User unknown", "permanent", nil)
	if err != nil {
		t.Fatalf("RecordAttempt failed: %v", err)
	}

	// Retrieve the message.
	m, err := s.FindMessageByID("TESTQUEUEID1")
	if err != nil {
		t.Fatalf("FindMessageByID failed: %v", err)
	}
	if m == nil {
		t.Fatal("Message not found")
	}

	if m.QueueID != "TESTQUEUEID1" {
		t.Errorf("Queue ID mismatch: got %s", m.QueueID)
	}
	if m.Status != "bounced" {
		t.Errorf("Status mismatch: got %s, want bounced", m.Status)
	}
	if len(m.Attempts) != 1 {
		t.Errorf("Attempts count mismatch: got %d, want 1", len(m.Attempts))
	}
	if m.Attempts[0].SMTPCode != 550 {
		t.Errorf("SMTP code mismatch: got %d, want 550", m.Attempts[0].SMTPCode)
	}
}

func TestSubjectRedaction(t *testing.T) {
	tmpDir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	s, err := Open(tmpDir, log, 90, false) // retain_subjects = false
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	err = s.RecordMessage(
		"SUBJECT-TEST",
		"client",
		"route",
		"from@example.com",
		"",
		string(recipients),
		"Personal Subject",
		"smtp",
		"10.0.0.1",
		now,
		expires,
		false,
	)
	if err != nil {
		t.Fatalf("RecordMessage failed: %v", err)
	}

	m, err := s.FindMessageByID("SUBJECT-TEST")
	if err != nil {
		t.Fatalf("FindMessageByID failed: %v", err)
	}
	if m.Subject != "" {
		t.Errorf("Subject not redacted: got %q, want empty", m.Subject)
	}
}

func TestFindBounces(t *testing.T) {
	s := testStore(t)

	// Record multiple messages with different statuses.
	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()

	testCases := []struct {
		id    string
		class string
	}{
		{"BOUNCE-1", "permanent"},
		{"BOUNCE-2", "permanent"},
		{"DELIVERED", "delivered"},
	}
	for i, tc := range testCases {
		expires := now.Add(96 * time.Hour)
		_ = s.RecordMessage(tc.id, "client", "route", "from@example.com", "", string(recipients), "Subject", "smtp", "10.0.0.1", now.Add(-time.Duration(i)*time.Hour), expires, false)
		_ = s.RecordAttempt(tc.id, 1, 550, "Error", tc.class, nil)
	}

	bounces, err := s.FindBounces(BounceFilter{Limit: 100})
	if err != nil {
		t.Fatalf("FindBounces failed: %v", err)
	}

	if len(bounces) != 2 {
		t.Errorf("Bounce count mismatch: got %d, want 2", len(bounces))
	}
	for _, b := range bounces {
		if b.Status != "bounced" {
			t.Errorf("Bounce status mismatch: got %s", b.Status)
		}
	}
}

func TestDeleteMessage(t *testing.T) {
	s := testStore(t)

	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	_ = s.RecordMessage("TO-DELETE", "client", "route", "from@example.com", "", string(recipients), "Subject", "smtp", "10.0.0.1", now, expires, false)

	err := s.DeleteMessage("TO-DELETE")
	if err != nil {
		t.Fatalf("DeleteMessage failed: %v", err)
	}

	m, err := s.FindMessageByID("TO-DELETE")
	if err != nil {
		t.Fatalf("FindMessageByID after delete failed: %v", err)
	}
	if m != nil {
		t.Fatal("Message still exists after delete")
	}
}

func TestRecordAudit(t *testing.T) {
	s := testStore(t)

	err := s.RecordAudit("admin-token", "192.168.1.1", "delete", "QUEUE-123", `{"reason":"test"}`)
	if err != nil {
		t.Fatalf("RecordAudit failed: %v", err)
	}
}

func TestFindAuditByQueueID(t *testing.T) {
	s := testStore(t)

	if err := s.RecordAudit("ops", "192.168.1.1", "requeue", "QUEUE-1", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAudit("ops", "192.168.1.1", "delete", "QUEUE-1", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAudit("ops", "192.168.1.1", "delete", "QUEUE-OTHER", ""); err != nil {
		t.Fatal(err)
	}

	entries, err := s.FindAuditByQueueID("QUEUE-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Action != "delete" || entries[1].Action != "requeue" {
		t.Fatalf("unexpected order: %+v", entries)
	}
}

// TestDeleteMessageCascadesAttempts guards against a regression to the bug
// where CREATE TABLE declared ON DELETE CASCADE but foreign key enforcement
// was never turned on for the connection, so SQLite silently ignored it and
// deleted messages left their attempts behind forever, defeating retention.
func TestDeleteMessageCascadesAttempts(t *testing.T) {
	s := testStore(t)

	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	_ = s.RecordMessage("CASCADE-TEST", "client", "route", "from@example.com", "", string(recipients), "Subject", "smtp", "10.0.0.1", now, now.Add(96*time.Hour), false)
	if err := s.RecordAttempt("CASCADE-TEST", 1, 421, "temporary failure", "temporary", nil); err != nil {
		t.Fatalf("RecordAttempt failed: %v", err)
	}

	if err := s.DeleteMessage("CASCADE-TEST"); err != nil {
		t.Fatalf("DeleteMessage failed: %v", err)
	}

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM attempts WHERE queue_id = ?", "CASCADE-TEST").Scan(&count); err != nil {
		t.Fatalf("counting attempts: %v", err)
	}
	if count != 0 {
		t.Errorf("attempts not cascaded on delete: %d rows remain", count)
	}
}

// TestRecordAttemptRejectsUnknownQueueID verifies that an attempt referencing
// a queue ID with no message row is rejected by the foreign key constraint
// instead of silently creating an orphan row.
func TestRecordAttemptRejectsUnknownQueueID(t *testing.T) {
	s := testStore(t)

	if err := s.RecordAttempt("NO-SUCH-QUEUE-ID", 1, 250, "ok", "delivered", nil); err == nil {
		t.Fatal("expected an error recording an attempt for a nonexistent queue ID, got nil")
	}
}

func TestFindMessagesFiltersByDerivedStatus(t *testing.T) {
	s := testStore(t)
	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	_ = s.RecordMessage("Q-QUEUED", "client", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now, expires, false)
	_ = s.RecordMessage("Q-DEFERRED", "client", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now, expires, false)
	_ = s.RecordAttempt("Q-DEFERRED", 1, 421, "try later", "temporary", nil)
	_ = s.RecordMessage("Q-DELIVERED", "client", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now, expires, false)
	_ = s.RecordAttempt("Q-DELIVERED", 1, 250, "ok", "delivered", nil)
	_ = s.RecordMessage("Q-BOUNCED", "client", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now, expires, false)
	_ = s.RecordAttempt("Q-BOUNCED", 1, 550, "no such user", "permanent", nil)

	for _, tc := range []struct {
		status string
		wantID string
	}{
		{"queued", "Q-QUEUED"},
		{"deferred", "Q-DEFERRED"},
		{"delivered", "Q-DELIVERED"},
		{"bounced", "Q-BOUNCED"},
	} {
		got, err := s.FindMessages(MessageFilter{Status: tc.status, Limit: 100})
		if err != nil {
			t.Fatalf("status %q: %v", tc.status, err)
		}
		if len(got) != 1 || got[0].QueueID != tc.wantID {
			t.Fatalf("status %q: got %v, want exactly [%s]", tc.status, got, tc.wantID)
		}
	}

	if _, err := s.FindMessages(MessageFilter{Status: "not-a-real-status", Limit: 100}); err == nil {
		t.Fatal("an unknown status value was silently accepted")
	}
}

func TestFindMessagesSenderAndSubjectFilters(t *testing.T) {
	s := testStore(t)
	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	_ = s.RecordMessage("SENDER-1", "client", "route", "printer@floor2.local", "", string(recipients), "Scan job 42", "smtp", "10.0.0.1", now, expires, true)
	_ = s.RecordMessage("SENDER-2", "client", "route", "erp@floor2.local", "", string(recipients), "Invoice", "smtp", "10.0.0.1", now, expires, true)

	got, err := s.FindMessages(MessageFilter{Sender: "printer@", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].QueueID != "SENDER-1" {
		t.Fatalf("sender filter: got %v", got)
	}

	got, err = s.FindMessages(MessageFilter{Subject: "Scan", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].QueueID != "SENDER-1" {
		t.Fatalf("subject filter: got %v", got)
	}
}

func TestFindMessagesActiveStatusIsQueuedOrDeferred(t *testing.T) {
	s := testStore(t)
	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	_ = s.RecordMessage("ACTIVE-QUEUED", "client", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now, expires, false)
	_ = s.RecordMessage("ACTIVE-DEFERRED", "client", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now, expires, false)
	_ = s.RecordAttempt("ACTIVE-DEFERRED", 1, 421, "try later", "temporary", nil)
	_ = s.RecordMessage("ACTIVE-DELIVERED", "client", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now, expires, false)
	_ = s.RecordAttempt("ACTIVE-DELIVERED", 1, 250, "ok", "delivered", nil)

	got, err := s.FindMessages(MessageFilter{Status: "active", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, m := range got {
		ids[m.QueueID] = true
	}
	if len(got) != 2 || !ids["ACTIVE-QUEUED"] || !ids["ACTIVE-DEFERRED"] {
		t.Fatalf("active filter: got %v", got)
	}
}

// TestFindMessagesStatusStableAcrossRapidAttempts guards the same
// same-second collision for FindMessages and CountQueue's "latest attempt"
// join: two attempts recorded back to back can land in the same
// second-precision at_time, and the join used to fan out into duplicate
// rows for one message instead of picking the actual most recent attempt.
func TestFindMessagesStatusStableAcrossRapidAttempts(t *testing.T) {
	s := testStore(t)
	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	_ = s.RecordMessage("RAPID-ATTEMPTS", "client", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now, now.Add(96*time.Hour), false)
	_ = s.RecordAttempt("RAPID-ATTEMPTS", 1, 421, "try later", "temporary", nil)
	_ = s.RecordAttempt("RAPID-ATTEMPTS", 2, 250, "ok", "delivered", nil)

	got, err := s.FindMessages(MessageFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows for one message, want 1 (join fanned out)", len(got))
	}
	if got[0].Status != "delivered" {
		t.Fatalf("status = %q, want delivered (the actual latest attempt)", got[0].Status)
	}

	stats, err := s.CountQueue()
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, st := range stats {
		total += st.Queued + st.Deferred + st.Delivered + st.Bounced
	}
	if total != 1 {
		t.Fatalf("CountQueue totals %d rows for one message, want 1", total)
	}
}

func TestFindMessagesSortIsAllowlisted(t *testing.T) {
	s := testStore(t)
	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	_ = s.RecordMessage("SORT-B", "client-b", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now, expires, false)
	_ = s.RecordMessage("SORT-A", "client-a", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now.Add(time.Second), expires, false)

	got, err := s.FindMessages(MessageFilter{Sort: "client", Order: "asc", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].QueueID != "SORT-A" || got[1].QueueID != "SORT-B" {
		t.Fatalf("sort by client asc not applied: %v", got)
	}

	// An unrecognised sort column must not reach the query text; it silently
	// falls back to the default (received_at) rather than being rejected.
	got, err = s.FindMessages(MessageFilter{Sort: "queue_id; DROP TABLE messages;--", Limit: 100})
	if err != nil {
		t.Fatalf("unknown sort column errored instead of falling back: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2 (table should not have been dropped)", len(got))
	}
}

func TestFindMessagesSortByStatus(t *testing.T) {
	s := testStore(t)
	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	_ = s.RecordMessage("SORT-BOUNCED", "client", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now, expires, false)
	_ = s.RecordAttempt("SORT-BOUNCED", 1, 550, "no", "permanent", nil)
	_ = s.RecordMessage("SORT-QUEUED", "client", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now, expires, false)
	_ = s.RecordMessage("SORT-DEFERRED", "client", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now, expires, false)
	_ = s.RecordAttempt("SORT-DEFERRED", 1, 421, "later", "temporary", nil)

	got, err := s.FindMessages(MessageFilter{Sort: "status", Order: "asc", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d rows, want 3", len(got))
	}
	want := []string{"SORT-QUEUED", "SORT-DEFERRED", "SORT-BOUNCED"}
	for i, id := range want {
		if got[i].QueueID != id {
			t.Fatalf("position %d: got %s, want %s (order: %v)", i, got[i].QueueID, id, got)
		}
	}
}

// TestFindBounceSummariesMatchesAPIShape also doubles as the regression test
// for a same-second collision in the "latest attempt" join: at_time has only
// second precision, so two attempts recorded within the same wall-clock
// second (as these two are, back to back with no delay) used to both match
// MAX(at_time) and fan the join out into two result rows for one message.
func TestFindBounceSummariesMatchesAPIShape(t *testing.T) {
	s := testStore(t)
	recipients, _ := json.Marshal([]string{"someone@partner.example"})
	now := time.Now()

	if err := s.RecordMessage("BOUNCE-SUMMARY-1", "printers-vienna", "m365", "relay@example.at", "kopierer@local",
		string(recipients), "Scan 2026-08-07", "smtp", "10.0.0.1", now, now.Add(96*time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAttempt("BOUNCE-SUMMARY-1", 1, 421, "try later", "temporary", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAttempt("BOUNCE-SUMMARY-1", 2, 550, "5.1.1 User unknown", "permanent", nil); err != nil {
		t.Fatal(err)
	}

	rows, hasMore, err := s.FindBounceSummaries(BounceFilter{Limit: 100})
	if err != nil {
		t.Fatalf("FindBounceSummaries: %v", err)
	}
	if hasMore {
		t.Fatal("hasMore true with fewer rows than the limit")
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	b := rows[0]
	if b.QueueID != "BOUNCE-SUMMARY-1" || b.Class != "permanent" || b.Attempts != 2 ||
		b.SMTPCode != 550 || b.SMTPResponse != "5.1.1 User unknown" || b.OriginalFrom != "kopierer@local" {
		t.Fatalf("unexpected summary: %+v", b)
	}
	if len(b.Recipients) != 1 || b.Recipients[0] != "someone@partner.example" {
		t.Fatalf("recipients not round-tripped: %+v", b.Recipients)
	}
	if b.FirstAttempt.IsZero() || b.LastAttempt.IsZero() || b.LastAttempt.Before(b.FirstAttempt) {
		t.Fatalf("first/last attempt timestamps wrong: %v / %v", b.FirstAttempt, b.LastAttempt)
	}
}

func TestFindBounceSummariesPagination(t *testing.T) {
	s := testStore(t)
	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("PAGE-BOUNCE-%d", i)
		_ = s.RecordMessage(id, "client", "route", "from@example.com", "", string(recipients), "s", "smtp", "10.0.0.1", now.Add(time.Duration(i)*time.Second), now.Add(96*time.Hour), false)
		_ = s.RecordAttempt(id, 1, 550, "no such user", "permanent", nil)
	}

	rows, hasMore, err := s.FindBounceSummaries(BounceFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || !hasMore {
		t.Fatalf("got %d rows, hasMore=%v; want 2 rows and hasMore=true", len(rows), hasMore)
	}

	rows2, hasMore2, err := s.FindBounceSummaries(BounceFilter{Limit: 2, Offset: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows2) != 1 || hasMore2 {
		t.Fatalf("got %d rows, hasMore=%v; want 1 row and hasMore=false", len(rows2), hasMore2)
	}
}

// TestFindMessagesRecipientFilterIsParameterized verifies that a SQL-shaped
// recipient filter is treated as a literal LIKE pattern, not SQL syntax.
func TestFindMessagesRecipientFilterIsParameterized(t *testing.T) {
	s := testStore(t)

	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	_ = s.RecordMessage("SQLI-TEST", "client", "route", "from@example.com", "", string(recipients), "Subject", "smtp", "10.0.0.1", now, now.Add(96*time.Hour), false)

	results, err := s.FindMessages(MessageFilter{Recipient: "' OR 1=1 --", Limit: 100})
	if err != nil {
		t.Fatalf("FindMessages with SQL-shaped filter errored instead of treating it as a literal: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("SQL-shaped recipient filter matched %d rows, want 0 (should be a literal substring, not injected SQL)", len(results))
	}
}
