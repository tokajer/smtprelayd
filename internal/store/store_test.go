// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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

// testRecord is the message a query test records when it does not care about
// the message itself, only about what the query does with it. A test that
// depends on a particular sender, client or subject overrides that one field
// on the returned value.
func testRecord(queueID string, received, expires time.Time) MessageRecord {
	return MessageRecord{
		QueueID:      queueID,
		Client:       "client",
		Route:        "route",
		EnvelopeFrom: "from@example.com",
		Recipients:   `["user@example.com"]`,
		Subject:      "Subject",
		Listener:     "smtp",
		RemoteAddr:   "10.0.0.1",
		MessageID:    "<test@example.com>",
		ContentType:  "text/plain",
		SizeBytes:    1024,
		HeaderCount:  8,
		Helo:         "device.local",
		ReceivedAt:   received,
		ExpiresAt:    expires,
	}
}

func TestRecordMessageAndAttempt(t *testing.T) {
	s := testStore(t)

	recipients, _ := json.Marshal([]string{"user@example.com"})
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	err := s.RecordMessage(MessageRecord{
		QueueID:      "TESTQUEUEID1",
		Client:       "printer-client",
		Route:        "m365",
		EnvelopeFrom: "relay@example.com",
		OriginalFrom: "printer@local",
		Recipients:   string(recipients),
		Subject:      "Test Subject",
		Listener:     "smtp",
		RemoteAddr:   "10.0.0.5",
		MessageID:    "<abc123@printer.local>",
		ContentType:  "text/plain; charset=utf-8",
		SizeBytes:    4096,
		HeaderCount:  9,
		Helo:         "printer.local",
		ReceivedAt:   now,
		ExpiresAt:    expires,
		TLSUsed:      true,
	})
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

	// The journal metadata and the last attempt's outcome both have to come
	// back on the message itself: the dashboard's list views and the API's
	// message object read them from there, not from the attempt list.
	if m.MessageID != "<abc123@printer.local>" || m.ContentType != "text/plain; charset=utf-8" {
		t.Errorf("journal headers mismatch: got %q / %q", m.MessageID, m.ContentType)
	}
	if m.SizeBytes != 4096 || m.HeaderCount != 9 || m.Helo != "printer.local" {
		t.Errorf("journal metadata mismatch: got %d bytes, %d headers, helo %q", m.SizeBytes, m.HeaderCount, m.Helo)
	}
	if m.LastCode != 550 || m.LastErr != "5.1.1 User unknown" || m.AttemptCount != 1 {
		t.Errorf("last attempt summary mismatch: got %d %q after %d attempts", m.LastCode, m.LastErr, m.AttemptCount)
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

	now := time.Now()
	rec := testRecord("SUBJECT-TEST", now, now.Add(96*time.Hour))
	rec.Subject = "Personal Subject"

	err = s.RecordMessage(rec)
	if err != nil {
		t.Fatalf("RecordMessage failed: %v", err)
	}

	// Two independent guarantees, both of which matter: nothing was written
	// to the column, and nothing readable comes back out of it. The second is
	// what protects rows stored while retain_subjects was still on, and it is
	// applied here rather than in the dashboard and the API separately.
	var raw string
	if err := s.db.QueryRow(`SELECT subject FROM messages WHERE queue_id = ?`, "SUBJECT-TEST").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if raw != "" {
		t.Errorf("subject column holds %q, want it never written", raw)
	}

	m, err := s.FindMessageByID("SUBJECT-TEST")
	if err != nil {
		t.Fatalf("FindMessageByID failed: %v", err)
	}
	if m.Subject != Redacted {
		t.Errorf("Subject = %q, want %q", m.Subject, Redacted)
	}
}

// The case the read-side policy exists for: a row written while subjects
// were retained must stop being readable once the setting is turned off.
func TestSubjectStoredBeforeRedactionIsHiddenAfterwards(t *testing.T) {
	dir := t.TempDir()
	on, err := Open(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rec := testRecord("SUBJECT-KEPT", now, now.Add(96*time.Hour))
	rec.Subject = "Personal Subject"
	if err := on.RecordMessage(rec); err != nil {
		t.Fatal(err)
	}
	if m, err := on.FindMessageByID("SUBJECT-KEPT"); err != nil {
		t.Fatal(err)
	} else if m.Subject != "Personal Subject" {
		t.Fatalf("with retention on, Subject = %q, want it kept", m.Subject)
	}
	if err := on.Close(); err != nil {
		t.Fatal(err)
	}

	off, err := Open(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), 90, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = off.Close() })
	m, err := off.FindMessageByID("SUBJECT-KEPT")
	if err != nil {
		t.Fatal(err)
	}
	if m.Subject != Redacted {
		t.Errorf("after turning retention off, Subject = %q, want %q", m.Subject, Redacted)
	}
}

func TestFindBounces(t *testing.T) {
	s := testStore(t)

	// Record multiple messages with different statuses.
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
		_ = s.RecordMessage(testRecord(tc.id, now.Add(-time.Duration(i)*time.Hour), expires))
		_ = s.RecordAttempt(tc.id, 1, 550, "Error", tc.class, nil)
	}

	bounces, _, err := s.FindBounces(BounceFilter{Limit: 100})
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

// TestRetentionCleanupCascadesAttempts pins the foreign key the retention
// job relies on: deleting a message row must take its attempts with it, or
// the attempts table grows forever while messages are pruned.
func TestRetentionCleanupCascadesAttempts(t *testing.T) {
	s := testStore(t)

	now := time.Now()
	_ = s.RecordMessage(testRecord("CASCADE-TEST", now, now.Add(96*time.Hour)))
	if err := s.RecordAttempt("CASCADE-TEST", 1, 421, "temporary failure", "temporary", nil); err != nil {
		t.Fatalf("RecordAttempt failed: %v", err)
	}

	// A cutoff a day past the retention window, so the row just written is
	// older than it.
	s.retentionCleanup(now.Add(s.retentionTTL + 24*time.Hour))
	m, err := s.FindMessageByID("CASCADE-TEST")
	if err != nil {
		t.Fatal(err)
	}
	if m != nil {
		t.Fatal("message row survived the retention cleanup")
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

// TestRecordRemovalAppendsAfterExistingAttempts guards against RecordRemoval
// colliding with a real delivery attempt's attempt_num after at least one
// retry already happened before the operator deleted the message.
func TestRecordRemovalAppendsAfterExistingAttempts(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	_ = s.RecordMessage(testRecord("REMOVE-AFTER-RETRY", now, now.Add(96*time.Hour)))
	_ = s.RecordAttempt("REMOVE-AFTER-RETRY", 1, 421, "try later", "temporary", nil)

	if err := s.RecordRemoval("REMOVE-AFTER-RETRY"); err != nil {
		t.Fatal(err)
	}

	msg, err := s.FindMessageByID("REMOVE-AFTER-RETRY")
	if err != nil {
		t.Fatal(err)
	}
	if msg.Status != "removed" {
		t.Fatalf("status = %q, want removed", msg.Status)
	}
	if len(msg.Attempts) != 2 || msg.Attempts[1].AttemptNum != 2 || msg.Attempts[1].Class != "removed" {
		t.Fatalf("unexpected attempts: %+v", msg.Attempts)
	}
}

// A message can be listed as queued or deferred while its spool copy is
// already gone: startup recovery drops a half-written pair, an operator
// deletes the files by hand, a crash lands between the unlink and the
// attempt row. The row then matches the "active" filter the queue view is
// built on forever, and every delete of it answered 404 -- nothing could
// clear it. ReconcileRemoved is what makes that state clearable.
func TestReconcileRemovedClearsAnActiveRow(t *testing.T) {
	s := testStore(t)
	now := time.Now()

	for _, tc := range []struct {
		id    string
		class string // "" means no attempt at all, i.e. status queued
	}{
		{"GHOST-QUEUED", ""},
		{"GHOST-DEFERRED", "temporary"},
	} {
		_ = s.RecordMessage(testRecord(tc.id, now, now.Add(96*time.Hour)))
		if tc.class != "" {
			_ = s.RecordAttempt(tc.id, 1, 421, "try later", tc.class, nil)
		}

		cleared, err := s.ReconcileRemoved(tc.id)
		if err != nil {
			t.Fatalf("%s: %v", tc.id, err)
		}
		if !cleared {
			t.Fatalf("%s: reported nothing to reconcile", tc.id)
		}
		msg, err := s.FindMessageByID(tc.id)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Status != "removed" {
			t.Fatalf("%s: status = %q, want removed", tc.id, msg.Status)
		}
	}
}

// The other half of the contract: a message that reached an outcome has no
// spool copy precisely because it is finished, and rewriting that into a
// removal would falsify the journal.
func TestReconcileRemovedLeavesFinishedRowsAlone(t *testing.T) {
	s := testStore(t)
	now := time.Now()

	for _, tc := range []struct{ id, class, want string }{
		{"DONE-DELIVERED", "delivered", "delivered"},
		{"DONE-BOUNCED", "permanent", "bounced"},
		{"DONE-REMOVED", "removed", "removed"},
	} {
		_ = s.RecordMessage(testRecord(tc.id, now, now.Add(96*time.Hour)))
		_ = s.RecordAttempt(tc.id, 1, 250, "response", tc.class, nil)

		cleared, err := s.ReconcileRemoved(tc.id)
		if err != nil {
			t.Fatalf("%s: %v", tc.id, err)
		}
		if cleared {
			t.Fatalf("%s: a finished message was rewritten into a removal", tc.id)
		}
		msg, err := s.FindMessageByID(tc.id)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Status != tc.want {
			t.Fatalf("%s: status = %q, want %q", tc.id, msg.Status, tc.want)
		}
		if len(msg.Attempts) != 1 {
			t.Fatalf("%s: attempts = %d, want 1", tc.id, len(msg.Attempts))
		}
	}

	cleared, err := s.ReconcileRemoved("NOSUCHMESSAGE000")
	if err != nil {
		t.Fatalf("unknown queue ID: %v", err)
	}
	if cleared {
		t.Fatal("unknown queue ID reported as reconciled")
	}
}

func TestFindMessagesFiltersByDerivedStatus(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	_ = s.RecordMessage(testRecord("Q-QUEUED", now, expires))
	_ = s.RecordMessage(testRecord("Q-DEFERRED", now, expires))
	_ = s.RecordAttempt("Q-DEFERRED", 1, 421, "try later", "temporary", nil)
	_ = s.RecordMessage(testRecord("Q-DELIVERED", now, expires))
	_ = s.RecordAttempt("Q-DELIVERED", 1, 250, "ok", "delivered", nil)
	_ = s.RecordMessage(testRecord("Q-BOUNCED", now, expires))
	_ = s.RecordAttempt("Q-BOUNCED", 1, 550, "no such user", "permanent", nil)

	_ = s.RecordMessage(testRecord("Q-REMOVED", now, expires))
	_ = s.RecordRemoval("Q-REMOVED")

	for _, tc := range []struct {
		status string
		wantID string
	}{
		{"queued", "Q-QUEUED"},
		{"deferred", "Q-DEFERRED"},
		{"delivered", "Q-DELIVERED"},
		{"bounced", "Q-BOUNCED"},
		{"removed", "Q-REMOVED"},
	} {
		got, _, err := s.FindMessages(MessageFilter{Status: tc.status, Limit: 100})
		if err != nil {
			t.Fatalf("status %q: %v", tc.status, err)
		}
		if len(got) != 1 || got[0].QueueID != tc.wantID {
			t.Fatalf("status %q: got %v, want exactly [%s]", tc.status, got, tc.wantID)
		}
	}

	if _, _, err := s.FindMessages(MessageFilter{Status: "not-a-real-status", Limit: 100}); err == nil {
		t.Fatal("an unknown status value was silently accepted")
	}
}

func TestFindMessagesSenderAndSubjectFilters(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	r := testRecord("SENDER-1", now, expires)
	r.EnvelopeFrom, r.Subject, r.TLSUsed = "printer@floor2.local", "Scan job 42", true
	_ = s.RecordMessage(r)
	r = testRecord("SENDER-2", now, expires)
	r.EnvelopeFrom, r.Subject, r.TLSUsed = "erp@floor2.local", "Invoice", true
	_ = s.RecordMessage(r)

	got, _, err := s.FindMessages(MessageFilter{Sender: "printer@", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].QueueID != "SENDER-1" {
		t.Fatalf("sender filter: got %v", got)
	}

	got, _, err = s.FindMessages(MessageFilter{Subject: "Scan", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].QueueID != "SENDER-1" {
		t.Fatalf("subject filter: got %v", got)
	}
}

func TestFindMessagesActiveStatusIsQueuedOrDeferred(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	_ = s.RecordMessage(testRecord("ACTIVE-QUEUED", now, expires))
	_ = s.RecordMessage(testRecord("ACTIVE-DEFERRED", now, expires))
	_ = s.RecordAttempt("ACTIVE-DEFERRED", 1, 421, "try later", "temporary", nil)
	_ = s.RecordMessage(testRecord("ACTIVE-DELIVERED", now, expires))
	_ = s.RecordAttempt("ACTIVE-DELIVERED", 1, 250, "ok", "delivered", nil)
	_ = s.RecordMessage(testRecord("ACTIVE-REMOVED", now, expires))
	_ = s.RecordRemoval("ACTIVE-REMOVED")

	got, _, err := s.FindMessages(MessageFilter{Status: "active", Limit: 100})
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

// TestFindMessagesStatusStableAcrossRapidAttempts guards the same-second
// collision in FindMessages' "latest attempt" join: two attempts recorded
// back to back can land in the same second-precision at_time, and the join
// used to fan out into duplicate rows for one message instead of picking the
// actual most recent attempt.
func TestFindMessagesStatusStableAcrossRapidAttempts(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	_ = s.RecordMessage(testRecord("RAPID-ATTEMPTS", now, now.Add(96*time.Hour)))
	_ = s.RecordAttempt("RAPID-ATTEMPTS", 1, 421, "try later", "temporary", nil)
	_ = s.RecordAttempt("RAPID-ATTEMPTS", 2, 250, "ok", "delivered", nil)

	got, _, err := s.FindMessages(MessageFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows for one message, want 1 (join fanned out)", len(got))
	}
	if got[0].Status != "delivered" {
		t.Fatalf("status = %q, want delivered (the actual latest attempt)", got[0].Status)
	}
}

func TestFindMessagesSortIsAllowlisted(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	r := testRecord("SORT-B", now, expires)
	r.Client = "client-b"
	_ = s.RecordMessage(r)
	r = testRecord("SORT-A", now.Add(time.Second), expires)
	r.Client = "client-a"
	_ = s.RecordMessage(r)

	got, _, err := s.FindMessages(MessageFilter{Sort: "client", Order: "asc", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].QueueID != "SORT-A" || got[1].QueueID != "SORT-B" {
		t.Fatalf("sort by client asc not applied: %v", got)
	}

	// An unrecognised sort column must not reach the query text; it silently
	// falls back to the default (received_at) rather than being rejected.
	got, _, err = s.FindMessages(MessageFilter{Sort: "queue_id; DROP TABLE messages;--", Limit: 100})
	if err != nil {
		t.Fatalf("unknown sort column errored instead of falling back: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2 (table should not have been dropped)", len(got))
	}
}

func TestFindMessagesSortByStatus(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	_ = s.RecordMessage(testRecord("SORT-BOUNCED", now, expires))
	_ = s.RecordAttempt("SORT-BOUNCED", 1, 550, "no", "permanent", nil)
	_ = s.RecordMessage(testRecord("SORT-QUEUED", now, expires))
	_ = s.RecordMessage(testRecord("SORT-DEFERRED", now, expires))
	_ = s.RecordAttempt("SORT-DEFERRED", 1, 421, "later", "temporary", nil)

	got, _, err := s.FindMessages(MessageFilter{Sort: "status", Order: "asc", Limit: 100})
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

	rec := testRecord("BOUNCE-SUMMARY-1", now, now.Add(96*time.Hour))
	rec.Client, rec.Route = "printers-vienna", "m365"
	rec.EnvelopeFrom, rec.OriginalFrom = "relay@example.at", "kopierer@local"
	rec.Recipients, rec.Subject, rec.TLSUsed = string(recipients), "Scan 2026-08-07", true
	if err := s.RecordMessage(rec); err != nil {
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
	now := time.Now()
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("PAGE-BOUNCE-%d", i)
		_ = s.RecordMessage(testRecord(id, now.Add(time.Duration(i)*time.Second), now.Add(96*time.Hour)))
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

	now := time.Now()
	_ = s.RecordMessage(testRecord("SQLI-TEST", now, now.Add(96*time.Hour)))

	results, _, err := s.FindMessages(MessageFilter{Recipient: "' OR 1=1 --", Limit: 100})
	if err != nil {
		t.Fatalf("FindMessages with SQL-shaped filter errored instead of treating it as a literal: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("SQL-shaped recipient filter matched %d rows, want 0 (should be a literal substring, not injected SQL)", len(results))
	}
}

// TestMigrationAddsJournalColumns covers the upgrade path: a database written
// by a version without the journal columns must gain them on the next Open,
// because CREATE TABLE IF NOT EXISTS silently leaves an existing table alone.
func TestMigrationAddsJournalColumns(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "spool"), 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "spool", "history.db")

	// The messages table exactly as the first released schema declared it.
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=rwc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE messages (
		queue_id TEXT PRIMARY KEY, client TEXT NOT NULL, route TEXT NOT NULL,
		envelope_from TEXT NOT NULL, original_from TEXT, recipients TEXT NOT NULL,
		subject TEXT, listener TEXT NOT NULL, remote_addr TEXT NOT NULL,
		received_at TEXT NOT NULL, expires_at TEXT NOT NULL, tls_used INTEGER NOT NULL,
		created_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"OLD-ROW", "client", "route", "from@example.com", "", `["user@example.com"]`,
		"Subject", "smtp", "10.0.0.1", ts, ts, 0, ts); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), 90, true)
	if err != nil {
		t.Fatalf("Open on a pre-journal database failed: %v", err)
	}
	defer s.Close()

	// A pre-migration row must still be readable, with the journal fields
	// reading as unknown rather than failing the scan.
	old, err := s.FindMessageByID("OLD-ROW")
	if err != nil {
		t.Fatalf("reading a pre-migration row failed: %v", err)
	}
	if old == nil {
		t.Fatal("pre-migration row disappeared")
	}
	if old.MessageID != "" || old.SizeBytes != 0 || old.Helo != "" {
		t.Errorf("pre-migration row invented journal values: %+v", old)
	}

	// And a row written after the migration must round-trip them.
	now := time.Now()
	if err := s.RecordMessage(testRecord("NEW-ROW", now, now.Add(time.Hour))); err != nil {
		t.Fatalf("RecordMessage after migration failed: %v", err)
	}
	fresh, err := s.FindMessageByID("NEW-ROW")
	if err != nil || fresh == nil {
		t.Fatalf("reading the post-migration row failed: %v", err)
	}
	if fresh.SizeBytes != 1024 || fresh.HeaderCount != 8 || fresh.Helo != "device.local" {
		t.Errorf("journal columns not written after migration: %+v", fresh)
	}
}

// The database holds every sender, recipient and subject, so it must not be
// left at the driver's default 0644 — and neither must the WAL sidecar,
// which holds the same rows before a checkpoint.
func TestDatabaseFilesAreNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not govern access on Windows; the data directory DACL does")
	}
	dir := t.TempDir()
	s, err := Open(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Force a write so the -wal sidecar exists.
	now := time.Now()
	if err := s.RecordMessage(testRecord("MODE-TEST", now, now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}

	base := filepath.Join(dir, "spool", "history.db")
	for _, path := range []string{base, base + "-wal", base + "-shm"} {
		fi, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue // sidecars are not guaranteed to exist at this moment
		}
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is mode %04o, want no group or other access", filepath.Base(path), fi.Mode().Perm())
		}
	}
}

// The class filter behind the dashboard's failure-class dropdown referenced
// a.class, a column the `a` subquery never selected, so every filtered request
// was a SQL error and a 500. Nothing covered it, which is why it survived.
func TestFindBouncesFiltersByClass(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	for i, tc := range []struct{ id, class string }{
		{"PERM-1", "permanent"},
		{"PERM-2", "permanent"},
		{"EXPIRED-1", "expired"},
		{"DELIVERED-1", "delivered"},
	} {
		_ = s.RecordMessage(testRecord(tc.id, now.Add(-time.Duration(i)*time.Hour), expires))
		_ = s.RecordAttempt(tc.id, 1, 550, "Error", tc.class, nil)
	}

	for class, want := range map[string]int{
		"permanent": 2,
		"expired":   1,
		"":          3, // no filter: every permanent and expired message
	} {
		got, _, err := s.FindBounces(BounceFilter{Class: class, Limit: 100})
		if err != nil {
			t.Fatalf("class=%q returned an error instead of rows: %v", class, err)
		}
		if len(got) != want {
			t.Errorf("class=%q returned %d bounces, want %d", class, len(got), want)
		}
	}

	// A message whose final attempt is not a failure must not appear under any
	// class, including its own.
	got, _, err := s.FindBounces(BounceFilter{Class: "delivered", Limit: 100})
	if err != nil {
		t.Fatalf("class=delivered: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("a delivered message appeared in the bounce view: %d rows", len(got))
	}
}

// The class shown is the final attempt's, so a message that failed temporarily
// before failing permanently must be found under "permanent", not "temporary".
func TestFindBouncesClassIsTheFinalAttempt(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	_ = s.RecordMessage(testRecord("RETRIED", now, now.Add(96*time.Hour)))
	_ = s.RecordAttempt("RETRIED", 1, 451, "try later", "temporary", nil)
	_ = s.RecordAttempt("RETRIED", 2, 550, "no such user", "permanent", nil)

	got, _, err := s.FindBounces(BounceFilter{Class: "permanent", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("class=permanent returned %d rows, want 1", len(got))
	}
	if got, _, err := s.FindBounces(BounceFilter{Class: "temporary", Limit: 100}); err != nil {
		t.Fatal(err)
	} else if len(got) != 0 {
		t.Errorf("an earlier temporary attempt matched the class filter: %d rows", len(got))
	}
}

// The DSN carried `_journal_mode=WAL` for months while the database ran in
// rollback-journal mode, because modernc's driver reads only `_pragma=`. That
// is the failure this test exists for: not "is WAL a good idea" but "did the
// setting take effect at all". Asserting the mode from the database itself is
// the only way to tell the two apart.
func TestJournalModeIsActuallyWAL(t *testing.T) {
	s := testStore(t)
	var mode string
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("reading journal_mode: %v", err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Fatalf("journal_mode is %q, want wal — the DSN pragma did not take effect", mode)
	}
}

// Foreign keys are the other setting that only works because it is spelled as
// a pragma, and the retention cascade silently stops working without it.
func TestForeignKeysAreOn(t *testing.T) {
	s := testStore(t)
	var on int
	if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&on); err != nil {
		t.Fatalf("reading foreign_keys: %v", err)
	}
	if on != 1 {
		t.Fatal("foreign_keys is off; ON DELETE CASCADE would be a no-op")
	}
}

// Every filter field, against all three query builders. The filter clauses
// and their argument binding are written out three times -- FindMessages,
// FindBounces, FindBounceSummaries -- and nothing detected a dropped one:
// deleting the client and route clauses from FindMessages outright left the
// whole suite green. A silently ignored filter is invisible, and it shows an
// operator other clients' mail in a view that claims to be filtered.
//
// The two rows differ in every filterable field, so a clause that fails to
// bind returns both instead of one.
func TestEveryFilterFieldBinds(t *testing.T) {
	s := testStore(t)
	early := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	late := early.Add(48 * time.Hour)

	for _, d := range []struct {
		id, client, route, from, rcpt, subj string
		at                                  time.Time
	}{
		{"aaaaaaaa", "alpha", "r-alpha", "from-alpha@x.test", `["to-alpha@y.test"]`, "subject-alpha", early},
		{"bbbbbbbb", "beta", "r-beta", "from-beta@x.test", `["to-beta@y.test"]`, "subject-beta", late},
	} {
		if err := s.RecordMessage(MessageRecord{
			QueueID: d.id, Client: d.client, Route: d.route, EnvelopeFrom: d.from,
			Recipients: d.rcpt, Subject: d.subj, Listener: "l", RemoteAddr: "127.0.0.1",
			ReceivedAt: d.at, ExpiresAt: d.at.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		// Permanent, so the same rows are visible to the bounce builders.
		if err := s.RecordAttempt(d.id, 1, 550, "rejected", "permanent", nil); err != nil {
			t.Fatal(err)
		}
	}

	afterEarly := late.Add(-time.Hour) // excludes the early row
	beforeLate := early.Add(time.Hour) // excludes the late row

	t.Run("FindMessages", func(t *testing.T) {
		for name, f := range map[string]MessageFilter{
			"client":    {Client: "alpha"},
			"route":     {Route: "r-alpha"},
			"sender":    {Sender: "from-alpha"},
			"recipient": {Recipient: "to-alpha"},
			"subject":   {Subject: "subject-alpha"},
			"since":     {Since: &afterEarly},
			"until":     {Until: &beforeLate},
		} {
			got, _, err := s.FindMessages(f)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if len(got) != 1 {
				t.Errorf("filter %q matched %d rows, want 1: the clause is not being applied", name, len(got))
			}
		}
	})

	t.Run("FindBounces", func(t *testing.T) {
		for name, f := range map[string]BounceFilter{
			"client":    {Client: "alpha"},
			"route":     {Route: "r-alpha"},
			"sender":    {Sender: "from-alpha"},
			"recipient": {Recipient: "to-alpha"},
			"subject":   {Subject: "subject-alpha"},
			"since":     {Since: &afterEarly},
			"until":     {Until: &beforeLate},
		} {
			got, _, err := s.FindBounces(f)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if len(got) != 1 {
				t.Errorf("filter %q matched %d rows, want 1: the clause is not being applied", name, len(got))
			}
		}
	})

	t.Run("FindBounceSummaries", func(t *testing.T) {
		for name, f := range map[string]BounceFilter{
			"client":    {Client: "alpha"},
			"route":     {Route: "r-alpha"},
			"sender":    {Sender: "from-alpha"},
			"recipient": {Recipient: "to-alpha"},
			"subject":   {Subject: "subject-alpha"},
		} {
			got, _, err := s.FindBounceSummaries(f)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if len(got) != 1 {
				t.Errorf("filter %q matched %d rows, want 1: the clause is not being applied", name, len(got))
			}
		}

		// Since and Until filter on the latest attempt here, not on
		// received_at, and both attempts were recorded in the same instant.
		// A window around now must therefore keep both rows and a window in
		// the past must drop both -- enough to prove the clause binds.
		future := time.Now().Add(24 * time.Hour)
		past := time.Now().Add(-24 * time.Hour)
		if got, _, err := s.FindBounceSummaries(BounceFilter{Since: &past, Until: &future}); err != nil || len(got) != 2 {
			t.Errorf("a window spanning now matched %d rows (err %v), want 2", len(got), err)
		}
		if got, _, err := s.FindBounceSummaries(BounceFilter{Since: &future}); err != nil || len(got) != 0 {
			t.Errorf("since in the future matched %d rows (err %v), want 0", len(got), err)
		}
		if got, _, err := s.FindBounceSummaries(BounceFilter{Until: &past}); err != nil || len(got) != 0 {
			t.Errorf("until in the past matched %d rows (err %v), want 0", len(got), err)
		}
	})
}

// TestConcurrentWritersNeverSeeBusy is what the DSN's busy_timeout is
// checked against. Sixteen writers, each recording a message and its attempt
// in a tight loop, ran clean under `cache=shared` (measured 2026-09-18, 1 280
// operations, 0 errors) and have to stay clean without it: with the file
// lock back in charge of the pool, a writer meeting another must wait, not
// fail.
func TestConcurrentWritersNeverSeeBusy(t *testing.T) {
	s := testStore(t)
	const writers, perWriter = 16, 40
	errs := make(chan error, writers*perWriter*2)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			now := time.Now()
			for i := 0; i < perWriter; i++ {
				id := fmt.Sprintf("W%02dN%021d", w, i)
				if err := s.RecordMessage(testRecord(id, now, now.Add(time.Hour))); err != nil {
					errs <- err
					continue
				}
				if err := s.RecordAttempt(id, 1, 250, "ok", "delivered", nil); err != nil {
					errs <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent write failed: %v", err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != writers*perWriter {
		t.Fatalf("%d messages recorded, want %d", n, writers*perWriter)
	}
}

// claimCleanup is the only thing the store's mutex still guards: exactly one
// caller per hour wins the slot, and the DELETE itself runs outside the lock.
func TestClaimCleanupHandsOutOneSlotPerHour(t *testing.T) {
	s := testStore(t)
	base := s.lastCleanup
	if s.claimCleanup(base.Add(30 * time.Minute)) {
		t.Fatal("cleanup claimed inside the hour")
	}
	if !s.claimCleanup(base.Add(61 * time.Minute)) {
		t.Fatal("cleanup not claimed after the hour")
	}
	if s.claimCleanup(base.Add(62 * time.Minute)) {
		t.Fatal("cleanup claimed twice for the same hour")
	}
}

// synchronous is the setting that decides what an accepted message costs in
// this file: under FULL each of the two implicit transactions per message
// fsyncs the WAL, which measured 119 message+attempt pairs a second on a
// Windows VM against 10 969 on Linux -- and 93 a second was the relay's whole
// sustained throughput there. Like journal_mode and foreign_keys it only
// takes effect because it is spelled as a `_pragma=` in the DSN; written any
// other way the driver ignores it and the default silently returns.
func TestSynchronousIsNormal(t *testing.T) {
	s := testStore(t)
	var mode int
	if err := s.db.QueryRow(`PRAGMA synchronous`).Scan(&mode); err != nil {
		t.Fatalf("reading synchronous: %v", err)
	}
	// 1 is NORMAL. 2 is FULL, the default, and is what this returns to if the
	// pragma stops being applied.
	if mode != 1 {
		t.Errorf("synchronous is %d, want 1 (NORMAL); every commit is paying for an fsync", mode)
	}
}

// The retention delete used to run inside RecordAttempt. Measured at a
// million rows it took 15.6 seconds, and SQLite has one writer: a delivery
// worker that ran it stopped every other writer -- the listener journalling
// incoming mail included -- for that whole time. RecordAttempt must now do
// nothing but insert.
func TestRecordAttemptDoesNotSweep(t *testing.T) {
	s := testStore(t)
	// Old enough to be past any retention window, so a sweep would take it.
	old := time.Now().UTC().Add(-365 * 24 * time.Hour)
	if err := s.RecordMessage(MessageRecord{
		QueueID: "QSWEEPAAAAAAAAAA", Client: "c", Route: "r",
		EnvelopeFrom: "a@b.at", Recipients: `["x@y.at"]`, Listener: "l",
		RemoteAddr: "127.0.0.1", ReceivedAt: old, ExpiresAt: old,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE messages SET created_at = ?`, old.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	// The store was opened more than an hour ago as far as the gate is
	// concerned only if we say so; force the slot open either way.
	s.mu.Lock()
	s.lastCleanup = old
	s.mu.Unlock()

	if err := s.RecordAttempt("QSWEEPAAAAAAAAAA", 1, 550, "no", "permanent", nil); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("RecordAttempt swept %d row(s); the sweep belongs to the dispatcher's tick", 1-n)
	}
}

// And the sweep itself still removes everything past the window, in chunks:
// more rows than one chunk holds, so the loop has to run more than once.
func TestRetentionSweepRemovesEverythingPastTheWindow(t *testing.T) {
	s := testStore(t)
	old := time.Now().UTC().Add(-365 * 24 * time.Hour)
	const rows = retentionChunk + 250
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO messages (queue_id, client, route, envelope_from,
		recipients, listener, remote_addr, received_at, expires_at, tls_used, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < rows; i++ {
		id := fmt.Sprintf("QCHUNK%010d", i)
		if _, err := stmt.Exec(id, "c", "r", "a@b.at", `["x@y.at"]`, "l", "127.0.0.1",
			old.Format(time.RFC3339), old.Format(time.RFC3339), 0, old.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	s.lastCleanup = old
	s.mu.Unlock()

	deleted := s.RetentionSweep(time.Now())
	if deleted != rows {
		t.Errorf("sweep deleted %d rows, want all %d: the chunk loop stopped early", deleted, rows)
	}
	var left int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Errorf("%d row(s) survived the sweep", left)
	}
	// The hourly gate still holds. Asserting that a second call deletes
	// nothing is not enough on its own -- with the table already empty that
	// passes with no gate at all -- so a fresh expired row goes in first. It
	// has to survive, because the slot for this hour is spent.
	if _, err := s.db.Exec(`INSERT INTO messages (queue_id, client, route, envelope_from,
		recipients, listener, remote_addr, received_at, expires_at, tls_used, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		"QGATEAAAAAAAAAAA", "c", "r", "a@b.at", `["x@y.at"]`, "l", "127.0.0.1",
		old.Format(time.RFC3339), old.Format(time.RFC3339), 0, old.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if again := s.RetentionSweep(time.Now()); again != 0 {
		t.Errorf("a second sweep within the hour deleted %d rows; the gate is not holding", again)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 1 {
		t.Errorf("the row inserted after the sweep is gone; the hourly gate did not hold")
	}
}

// The summary columns replace what the list queries used to derive by
// grouping the whole attempts table, so they have to agree with that table
// exactly -- a drift here is invisible, because nothing counts any more.
func TestAttemptSummaryMatchesTheAttemptsTable(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	const id = "QSUMMARYAAAAAAAA"
	if err := s.RecordMessage(MessageRecord{
		QueueID: id, Client: "c", Route: "r", EnvelopeFrom: "a@b.at",
		Recipients: `["x@y.at"]`, Listener: "l", RemoteAddr: "127.0.0.1",
		ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	for i, a := range []struct {
		code  int
		resp  string
		class string
	}{
		{451, "4.3.0 try later", "temporary"},
		{451, "4.3.0 try later", "temporary"},
		{250, "2.0.0 OK", "delivered"},
	} {
		if err := s.RecordAttempt(id, i+1, a.code, a.resp, a.class, nil); err != nil {
			t.Fatal(err)
		}
	}

	var count int
	var lastClass, lastResp string
	var lastCode int
	var first, last string
	if err := s.db.QueryRow(`SELECT attempt_count, last_class, last_smtp_code,
		last_smtp_response, first_attempt_at, last_attempt_at FROM messages WHERE queue_id = ?`, id).
		Scan(&count, &lastClass, &lastCode, &lastResp, &first, &last); err != nil {
		t.Fatal(err)
	}

	var wantCount int
	var wantClass, wantResp, wantFirst, wantLast string
	var wantCode int
	if err := s.db.QueryRow(`SELECT COUNT(*), MIN(at_time), MAX(at_time) FROM attempts WHERE queue_id = ?`, id).
		Scan(&wantCount, &wantFirst, &wantLast); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT class, smtp_code, smtp_response FROM attempts
		WHERE queue_id = ? ORDER BY id DESC LIMIT 1`, id).Scan(&wantClass, &wantCode, &wantResp); err != nil {
		t.Fatal(err)
	}

	if count != wantCount {
		t.Errorf("attempt_count = %d, the attempts table holds %d", count, wantCount)
	}
	if lastClass != wantClass || lastCode != wantCode || lastResp != wantResp {
		t.Errorf("last attempt summarised as (%s, %d, %q), the table says (%s, %d, %q)",
			lastClass, lastCode, lastResp, wantClass, wantCode, wantResp)
	}
	if first != wantFirst || last != wantLast {
		t.Errorf("attempt window %s..%s, the table says %s..%s", first, last, wantFirst, wantLast)
	}
}

// has_bounced exists as its own column rather than as a test on last_class
// because the two are different questions. A message that failed permanently
// and was then requeued and delivered belongs in the bounce view -- that
// failure happened -- while its latest attempt says "delivered".
func TestABounceStaysABounceAfterARequeueAndDelivery(t *testing.T) {
	s := testStore(t)
	now := time.Now().UTC()
	const id = "QREBOUNDAAAAAAAA"
	if err := s.RecordMessage(MessageRecord{
		QueueID: id, Client: "c", Route: "r", EnvelopeFrom: "a@b.at",
		Recipients: `["x@y.at"]`, Listener: "l", RemoteAddr: "127.0.0.1",
		ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAttempt(id, 1, 550, "5.1.1 unknown", "permanent", nil); err != nil {
		t.Fatal(err)
	}
	if got, _, err := s.FindBounces(BounceFilter{Limit: 10}); err != nil || len(got) != 1 {
		t.Fatalf("after the permanent failure: %d bounces, err %v", len(got), err)
	}

	// Requeued by an operator, and this time it goes out.
	if err := s.RecordAttempt(id, 2, 250, "2.0.0 OK", "delivered", nil); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.FindBounces(BounceFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("the message left the bounce view after a later delivery: %d rows", len(got))
	}
	if got[0].LastCode != 250 {
		t.Errorf("the bounce row shows code %d, want the latest attempt's 250", got[0].LastCode)
	}
	// And the class filter still selects on the latest attempt.
	if rows, _, err := s.FindBounces(BounceFilter{Class: "permanent", Limit: 10}); err != nil || len(rows) != 0 {
		t.Errorf("filtering on class permanent matched %d rows; the latest attempt is delivered", len(rows))
	}
}

// The list queries no longer count attempts; they read the summary columns.
// A database written before those columns existed therefore has to be
// backfilled on the next Open, or every old message reads as "never
// attempted" -- which for an old bounce is not stale but wrong, and would
// empty the bounce view of everything that happened before the upgrade.
func TestMigrationBackfillsAttemptSummaries(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "spool"), 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "spool", "history.db")

	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=rwc")
	if err != nil {
		t.Fatal(err)
	}
	// The schema as it stood with the journal columns but before the
	// summaries, which is what an installed relay upgrading to this version
	// actually has on disk.
	if _, err := db.Exec(`CREATE TABLE messages (
		queue_id TEXT PRIMARY KEY, client TEXT NOT NULL, route TEXT NOT NULL,
		envelope_from TEXT NOT NULL, original_from TEXT, recipients TEXT NOT NULL,
		subject TEXT, listener TEXT NOT NULL, remote_addr TEXT NOT NULL,
		received_at TEXT NOT NULL, expires_at TEXT NOT NULL, tls_used INTEGER NOT NULL,
		created_at TEXT NOT NULL, message_id TEXT, content_type TEXT,
		size_bytes INTEGER, header_count INTEGER, helo TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE attempts (
		id INTEGER PRIMARY KEY AUTOINCREMENT, queue_id TEXT NOT NULL,
		attempt_num INTEGER NOT NULL, at_time TEXT NOT NULL, smtp_code INTEGER,
		smtp_response TEXT, class TEXT NOT NULL, next_attempt_at TEXT,
		created_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}

	base := time.Now().UTC().Add(-time.Hour)
	ts := func(d time.Duration) string { return base.Add(d).Format(time.RFC3339) }
	for _, m := range []string{"OLD-BOUNCE", "OLD-DELIVERED"} {
		if _, err := db.Exec(`INSERT INTO messages
			(queue_id, client, route, envelope_from, original_from, recipients, subject,
			 listener, remote_addr, received_at, expires_at, tls_used, created_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			m, "client", "route", "from@example.com", "", `["user@example.com"]`, "Subject",
			"smtp", "10.0.0.1", ts(0), ts(time.Hour), 0, ts(0)); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []struct {
		id    string
		num   int
		at    time.Duration
		code  int
		class string
	}{
		{"OLD-BOUNCE", 1, time.Minute, 451, "temporary"},
		{"OLD-BOUNCE", 2, 2 * time.Minute, 550, "permanent"},
		{"OLD-DELIVERED", 1, time.Minute, 250, "delivered"},
	} {
		if _, err := db.Exec(`INSERT INTO attempts
			(queue_id, attempt_num, at_time, smtp_code, smtp_response, class, created_at)
			VALUES (?,?,?,?,?,?,?)`,
			a.id, a.num, ts(a.at), a.code, "response", a.class, ts(a.at)); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), 90, true)
	if err != nil {
		t.Fatalf("Open on a pre-summary database failed: %v", err)
	}
	defer s.Close()

	// The bounce survives the upgrade and knows what happened to it.
	bounces, _, err := s.FindBounces(BounceFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(bounces) != 1 || bounces[0].QueueID != "OLD-BOUNCE" {
		t.Fatalf("after the upgrade the bounce view holds %d rows, want the one old bounce", len(bounces))
	}
	if bounces[0].AttemptCount != 2 {
		t.Errorf("the backfilled attempt count is %d, want 2", bounces[0].AttemptCount)
	}
	if bounces[0].LastCode != 550 {
		t.Errorf("the backfilled last code is %d, want the permanent failure's 550", bounces[0].LastCode)
	}

	// And the delivered message is not in it, nor counted as never attempted.
	all, _, err := s.FindMessages(MessageFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all {
		if m.QueueID == "OLD-DELIVERED" {
			if m.Status != "delivered" {
				t.Errorf("the delivered message reads as %q after the upgrade", m.Status)
			}
			if m.AttemptCount != 1 {
				t.Errorf("its backfilled attempt count is %d, want 1", m.AttemptCount)
			}
		}
	}
}

// An index the planner never chooses is pure write cost, and on the journal
// path that cost is measured: the summary columns and their indexes took it
// from 2 829 message+attempt pairs a second to 1 096. idx_messages_lastattempt
// was one of those indexes and earned nothing -- EXPLAIN QUERY PLAN takes
// idx_messages_bounced for the filter and sorts in a temp b-tree regardless.
// A database that already has it must lose it, or it keeps paying.
func TestAnIndexThatEarnedNothingIsDropped(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "spool"), 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "spool", "history.db")

	// A database from the version that created it.
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=rwc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE messages (
		queue_id TEXT PRIMARY KEY, client TEXT NOT NULL, route TEXT NOT NULL,
		envelope_from TEXT NOT NULL, original_from TEXT, recipients TEXT NOT NULL,
		subject TEXT, listener TEXT NOT NULL, remote_addr TEXT NOT NULL,
		received_at TEXT NOT NULL, expires_at TEXT NOT NULL, tls_used INTEGER NOT NULL,
		created_at TEXT NOT NULL, last_attempt_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE INDEX idx_messages_lastattempt ON messages(last_attempt_at)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), 90, true)
	if err != nil {
		t.Fatalf("Open on a database carrying the dropped index failed: %v", err)
	}
	defer s.Close()

	var n int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`,
		"idx_messages_lastattempt").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("the unused index survived the upgrade; every write still pays for it")
	}

	// The two that do earn their keep are there.
	for _, want := range []string{"idx_messages_bounced", "idx_messages_lastclass"} {
		if err := s.db.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, want).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("%s is missing; the queries that need it fall back to a scan", want)
		}
	}
}
