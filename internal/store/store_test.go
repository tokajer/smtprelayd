// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package store

import (
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	tmpDir := t.TempDir()
	log := slog.New(slog.NewTextHandler(nil, nil))

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
	log := slog.New(slog.NewTextHandler(nil, nil))

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
