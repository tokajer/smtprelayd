// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package spool

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnqueueClaimRemove(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{From: "a@example.at", To: []string{"b@example.net"}, Client: "c", Route: "r",
		Received: time.Now().UTC()}
	id, err := s.Enqueue(env, strings.NewReader("Subject: x\r\n\r\nbody\r\n"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := s.Claim(time.Now())
	if !ok || m.ID != id {
		t.Fatalf("Claim returned %v %v", m, ok)
	}
	if _, ok := s.Claim(time.Now()); ok {
		t.Fatal("a leased message was handed out twice")
	}
	f, err := s.Open(id)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if !strings.Contains(string(b), "body") {
		t.Fatalf("body not stored: %q", b)
	}
	if err := s.Remove(id); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 0 {
		t.Fatalf("queue length %d after removal", s.Len())
	}
	// The index dropping the entry is not enough: a body left on disk would
	// occupy the spool quota until the next restart cleaned it up.
	for _, ext := range []string{".json", ".eml"} {
		if _, err := os.Stat(filepath.Join(dir, "spool", "queue", id.String()+ext)); !os.IsNotExist(err) {
			t.Fatalf("%s survived Remove: %v", ext, err)
		}
	}
}

func TestEnqueueEnforcesSizeLimit(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Enqueue(Envelope{}, strings.NewReader(strings.Repeat("x", 2048)), 1024, time.Hour)
	if err != ErrTooLarge {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	// An aborted enqueue must not leave anything behind.
	entries, _ := os.ReadDir(filepath.Join(dir, "spool", "tmp"))
	if len(entries) != 0 {
		t.Fatalf("tmp directory not cleaned: %v", entries)
	}
	if s.Len() != 0 {
		t.Fatalf("queue length %d after a rejected enqueue", s.Len())
	}
}

func TestRecoveryDropsOrphanedBody(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Enqueue(Envelope{From: "a@example.at"}, strings.NewReader("x"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash between the body and the metadata rename.
	if err := os.Remove(filepath.Join(dir, "spool", "queue", id.String()+".json")); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 0 {
		t.Fatalf("orphaned body was recovered as a message")
	}
	if _, err := os.Stat(filepath.Join(dir, "spool", "queue", id.String()+".eml")); !os.IsNotExist(err) {
		t.Fatal("orphaned body was not removed")
	}
}

func TestQueueDepthSplitsQueuedAndDeferred(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	env1 := Envelope{From: "a@example.at", To: []string{"b@example.net"}, Route: "r1", Received: time.Now().UTC()}
	env2 := Envelope{From: "a@example.at", To: []string{"b@example.net"}, Route: "r1", Received: time.Now().UTC().Add(time.Second)}
	if _, err := s.Enqueue(env1, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue(env2, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}

	// Claim one and release it with a future retry time, simulating a
	// deferred delivery; the other stays untouched and claimable.
	m, ok := s.Claim(time.Now())
	if !ok {
		t.Fatal("claim failed")
	}
	m.NextAttempt = time.Now().Add(time.Hour)
	if err := s.Release(m); err != nil {
		t.Fatal(err)
	}

	depth := s.QueueDepth(time.Now())
	got := depth["r1"]
	if got.Queued != 1 || got.Deferred != 1 {
		t.Fatalf("got %+v, want 1 queued and 1 deferred", got)
	}
}

func TestQueueDepthCountsLeasedMessageAsQueued(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{From: "a@example.at", To: []string{"b@example.net"}, Route: "r1", Received: time.Now().UTC()}
	if _, err := s.Enqueue(env, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Claim(time.Now()); !ok {
		t.Fatal("claim failed")
	}

	depth := s.QueueDepth(time.Now())
	got := depth["r1"]
	if got.Queued != 1 || got.Deferred != 0 {
		t.Fatalf("got %+v, want the in-flight message counted as queued", got)
	}
}

func TestFailMovesAside(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	id, err := s.Enqueue(Envelope{From: "a@example.at"}, strings.NewReader("x"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := s.Claim(time.Now())
	if err := s.Fail(m, "550 rejected"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "spool", "failed", id.String()+".eml")); err != nil {
		t.Fatalf("failed message was not preserved: %v", err)
	}
}

func TestRequeueFromFailedResetsAttemptsAndMovesFiles(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	id, err := s.Enqueue(Envelope{From: "a@example.at", Route: "r1"}, strings.NewReader("body"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := s.Claim(time.Now())
	m.Attempts = 3
	if err := s.Fail(m, "550 rejected"); err != nil {
		t.Fatal(err)
	}

	if err := s.Requeue(id); err != nil {
		t.Fatalf("Requeue: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "spool", "failed", id.String()+".eml")); !os.IsNotExist(err) {
		t.Fatalf("body still present in failed/: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "spool", "failed", id.String()+".json")); !os.IsNotExist(err) {
		t.Fatalf("metadata still present in failed/: %v", err)
	}

	got, ok := s.Claim(time.Now())
	if !ok || got.ID != id {
		t.Fatalf("requeued message not claimable: %v %v", got, ok)
	}
	if got.Attempts != 0 {
		t.Fatalf("attempts = %d, want reset to 0", got.Attempts)
	}
	f, err := s.Open(id)
	if err != nil {
		t.Fatalf("body not readable after requeue: %v", err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if !strings.Contains(string(b), "body") {
		t.Fatalf("body content lost across requeue: %q", b)
	}
}

func TestRequeueActiveMessageResetsAttempts(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	id, err := s.Enqueue(Envelope{From: "a@example.at", Route: "r1"}, strings.NewReader("x"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := s.Claim(time.Now())
	m.Attempts = 2
	m.NextAttempt = time.Now().Add(time.Hour)
	if err := s.Release(m); err != nil {
		t.Fatal(err)
	}

	if err := s.Requeue(id); err != nil {
		t.Fatalf("Requeue: %v", err)
	}
	got, ok := s.Claim(time.Now())
	if !ok || got.Attempts != 0 {
		t.Fatalf("got %v %v, want attempts reset to 0 and immediately claimable", got, ok)
	}
}

func TestRequeueUnknownIDReturnsNotFound(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Requeue(id); err != ErrNotFound {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestRequeueAndDiscardRefuseALeasedMessage(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	id, err := s.Enqueue(Envelope{From: "a@example.at"}, strings.NewReader("x"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Claim(time.Now()); !ok {
		t.Fatal("claim failed")
	}
	if err := s.Requeue(id); err != ErrBusy {
		t.Fatalf("Requeue on a leased message: got %v, want ErrBusy", err)
	}
	if err := s.Discard(id); err != ErrBusy {
		t.Fatalf("Discard on a leased message: got %v, want ErrBusy", err)
	}
}

func TestDiscardRemovesActiveMessage(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	id, err := s.Enqueue(Envelope{From: "a@example.at"}, strings.NewReader("x"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Discard(id); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if s.Len() != 0 {
		t.Fatalf("queue length %d after Discard", s.Len())
	}
	for _, ext := range []string{".json", ".eml"} {
		if _, err := os.Stat(filepath.Join(dir, "spool", "queue", id.String()+ext)); !os.IsNotExist(err) {
			t.Fatalf("%s survived Discard: %v", ext, err)
		}
	}
}

func TestDiscardRemovesFailedMessage(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	id, err := s.Enqueue(Envelope{From: "a@example.at"}, strings.NewReader("x"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := s.Claim(time.Now())
	if err := s.Fail(m, "550 rejected"); err != nil {
		t.Fatal(err)
	}
	if err := s.Discard(id); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	for _, ext := range []string{".json", ".eml"} {
		if _, err := os.Stat(filepath.Join(dir, "spool", "failed", id.String()+ext)); !os.IsNotExist(err) {
			t.Fatalf("%s survived Discard: %v", ext, err)
		}
	}
}

func TestDiscardUnknownIDReturnsNotFound(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Discard(id); err != ErrNotFound {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestQueueDepthOldestQueuedTracksEarliestClaimable(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	older := time.Now().UTC().Add(-time.Hour)
	newer := time.Now().UTC()
	if _, err := s.Enqueue(Envelope{From: "a@example.at", Route: "r1", Received: newer}, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue(Envelope{From: "a@example.at", Route: "r1", Received: older}, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	depth := s.QueueDepth(time.Now())
	got := depth["r1"].OldestQueued
	if !got.Equal(older) {
		t.Fatalf("OldestQueued = %v, want %v", got, older)
	}
}

// enqueueAndFail puts one message through the queue and into spool/failed,
// which is where the quota used to lose sight of it.
func enqueueAndFail(t *testing.T, s *Spool, body string) ID {
	t.Helper()
	env := Envelope{From: "a@example.at", To: []string{"b@example.net"}, Client: "c", Route: "r",
		Received: time.Now().UTC()}
	id, err := s.Enqueue(env, strings.NewReader(body), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := s.Claim(time.Now())
	if !ok {
		t.Fatal("nothing to claim")
	}
	if err := s.Fail(m, "550 nope"); err != nil {
		t.Fatal(err)
	}
	return id
}

// Fail() used to drop the message from the only index spoolSize() summed, so a
// client that produced nothing but permanent failures freed its own quota on
// every message while continuing to fill the filesystem.
func TestFailedMessagesStillCountTowardsTheQuota(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := s.spoolSize(); got != 0 {
		t.Fatalf("empty spool reports %d bytes", got)
	}

	enqueueAndFail(t, s, "Subject: x\r\n\r\n"+strings.Repeat("z", 4096)+"\r\n")

	after := s.spoolSize()
	if after == 0 {
		t.Fatal("a failed message freed its quota while still occupying the disk")
	}
	if after < 4096 {
		t.Fatalf("failed message accounted as %d bytes, want at least the body", after)
	}
}

// The other half: the quota must be released when the files really do go, by
// either of the two ways out of spool/failed.
func TestQuotaIsReleasedWhenFailedFilesGo(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  func(*Spool, ID) error
	}{
		{"discard", func(s *Spool, id ID) error { return s.Discard(id) }},
		{"requeue", func(s *Spool, id ID) error { return s.Requeue(id) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			id := enqueueAndFail(t, s, "Subject: x\r\n\r\nbody\r\n")
			if len(s.failedIndex) != 1 {
				t.Fatalf("failed index holds %d entries", len(s.failedIndex))
			}
			if err := tc.out(s, id); err != nil {
				t.Fatal(err)
			}
			if len(s.failedIndex) != 0 {
				t.Fatalf("%s left %d entries in the failed index", tc.name, len(s.failedIndex))
			}
		})
	}
}

// Counting alone would mean a full spool/failed permanently refuses new mail.
// The sweep is what makes the quota recoverable without an operator.
func TestSweepFailedHonoursRetention(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := enqueueAndFail(t, s, "Subject: x\r\n\r\nbody\r\n")

	// Retention of zero keeps everything, which is the documented opt-out.
	if removed, _ := s.SweepFailed(time.Now().Add(365 * 24 * time.Hour)); removed != 0 {
		t.Fatalf("a zero retention swept %d messages", removed)
	}

	s.SetFailedRetention(48 * time.Hour)
	if removed, _ := s.SweepFailed(time.Now().Add(24 * time.Hour)); removed != 0 {
		t.Fatalf("swept %d messages before the retention elapsed", removed)
	}

	removed, freed := s.SweepFailed(time.Now().Add(72 * time.Hour))
	if removed != 1 || freed == 0 {
		t.Fatalf("SweepFailed removed %d freeing %d, want 1 and non-zero", removed, freed)
	}
	for _, ext := range []string{".json", ".eml"} {
		if _, err := os.Stat(filepath.Join(dir, "spool", "failed", id.String()+ext)); !os.IsNotExist(err) {
			t.Errorf("%s survived the sweep: %v", ext, err)
		}
	}
	if got := s.spoolSize(); got != 0 {
		t.Fatalf("spool still accounts %d bytes after the sweep", got)
	}
}

// A restart must not lose sight of what is already in spool/failed, or the
// quota would be wrong again for every message that failed before it.
func TestFailedIndexSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	enqueueAndFail(t, s, "Subject: x\r\n\r\n"+strings.Repeat("z", 2048)+"\r\n")
	before := s.spoolSize()

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.spoolSize(); got != before {
		t.Fatalf("after reopen the spool accounts %d bytes, want %d", got, before)
	}
}

// A negative spool_max_gb, or one large enough to wrap the gigabytes-to-bytes
// multiplication, used to mean "no quota at all".
func TestSetQuotaNeverWrapsIntoNoQuota(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.SetQuota(1<<40, 80)
	if s.maxQuotaBytes <= 0 {
		t.Fatalf("an enormous quota became %d, i.e. no quota", s.maxQuotaBytes)
	}
	s.SetQuota(-1, 80)
	if s.maxQuotaBytes != 0 {
		t.Fatalf("a negative quota became %d, want 0 (no quota)", s.maxQuotaBytes)
	}
}
