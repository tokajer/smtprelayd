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

	now := time.Now()
	expires := now.Add(96 * time.Hour)

	_ = s.RecordMessage(testRecord("TO-DELETE", now, expires))

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

	now := time.Now()
	_ = s.RecordMessage(testRecord("CASCADE-TEST", now, now.Add(96*time.Hour)))
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
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	_ = s.RecordMessage(testRecord("Q-QUEUED", now, expires))
	_ = s.RecordMessage(testRecord("Q-DEFERRED", now, expires))
	_ = s.RecordAttempt("Q-DEFERRED", 1, 421, "try later", "temporary", nil)
	_ = s.RecordMessage(testRecord("Q-DELIVERED", now, expires))
	_ = s.RecordAttempt("Q-DELIVERED", 1, 250, "ok", "delivered", nil)
	_ = s.RecordMessage(testRecord("Q-BOUNCED", now, expires))
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
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	r := testRecord("SENDER-1", now, expires)
	r.EnvelopeFrom, r.Subject, r.TLSUsed = "printer@floor2.local", "Scan job 42", true
	_ = s.RecordMessage(r)
	r = testRecord("SENDER-2", now, expires)
	r.EnvelopeFrom, r.Subject, r.TLSUsed = "erp@floor2.local", "Invoice", true
	_ = s.RecordMessage(r)

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
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	_ = s.RecordMessage(testRecord("ACTIVE-QUEUED", now, expires))
	_ = s.RecordMessage(testRecord("ACTIVE-DEFERRED", now, expires))
	_ = s.RecordAttempt("ACTIVE-DEFERRED", 1, 421, "try later", "temporary", nil)
	_ = s.RecordMessage(testRecord("ACTIVE-DELIVERED", now, expires))
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
	now := time.Now()
	_ = s.RecordMessage(testRecord("RAPID-ATTEMPTS", now, now.Add(96*time.Hour)))
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
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	r := testRecord("SORT-B", now, expires)
	r.Client = "client-b"
	_ = s.RecordMessage(r)
	r = testRecord("SORT-A", now.Add(time.Second), expires)
	r.Client = "client-a"
	_ = s.RecordMessage(r)

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
	now := time.Now()
	expires := now.Add(96 * time.Hour)

	_ = s.RecordMessage(testRecord("SORT-BOUNCED", now, expires))
	_ = s.RecordAttempt("SORT-BOUNCED", 1, 550, "no", "permanent", nil)
	_ = s.RecordMessage(testRecord("SORT-QUEUED", now, expires))
	_ = s.RecordMessage(testRecord("SORT-DEFERRED", now, expires))
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

	results, err := s.FindMessages(MessageFilter{Recipient: "' OR 1=1 --", Limit: 100})
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
