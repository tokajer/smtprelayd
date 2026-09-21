// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package spool

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	f, err := s.OpenBody(id)
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
	f, err := s.OpenBody(id)
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

// Has is what lets the dashboard's queue view, which is built from the
// history store, tell a message it can still act on from one whose spool
// copy is already gone.
func TestHasCoversQueuedFailedAndDiscarded(t *testing.T) {
	s, _ := Open(t.TempDir())
	id, err := s.Enqueue(Envelope{From: "a@example.at"}, strings.NewReader("x"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Has(id) {
		t.Fatal("a queued message reported as absent")
	}

	failed := enqueueAndFail(t, s, "y")
	if !s.Has(failed) {
		t.Fatal("a permanently failed message reported as absent; it can still be requeued")
	}

	if err := s.Discard(id); err != nil {
		t.Fatal(err)
	}
	if s.Has(id) {
		t.Fatal("a discarded message still reported as present")
	}
	if s.Has(ID("../../etc/passwd")) {
		t.Fatal("an invalid queue id reported as present")
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

// QuotaWarning backs the "spool is filling up" log line, so it must report
// exactly the state limits.spool_warn_percent describes: no warning without
// both a quota and a threshold configured, and a clean flip once usage
// reaches the threshold.
func TestQuotaWarningReportsThresholdCrossing(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// No quota: over must stay false no matter how much is enqueued.
	s.SetQuota(0, 80)
	if _, err := s.Enqueue(Envelope{}, strings.NewReader(strings.Repeat("x", 4096)), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, over := s.QuotaWarning(); over {
		t.Fatal("QuotaWarning reported over with no quota configured")
	}

	// A quota with no warning threshold: over must stay false regardless of
	// usage. SetQuota's gigabyte granularity is too coarse to test a byte
	// threshold against, but that does not matter here since warnPercent of
	// 0 short-circuits the comparison before usage is even considered.
	s.SetQuota(1, 0)
	if _, _, over := s.QuotaWarning(); over {
		t.Fatal("QuotaWarning reported over with no warning threshold configured")
	}

	// A quota and a threshold: set the unexported fields directly, since
	// SetQuota cannot express a precise byte threshold to test against.
	s2, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s2.maxQuotaBytes = 1000
	s2.warnQuotaPercent = 80

	if _, err := s2.Enqueue(Envelope{}, strings.NewReader(strings.Repeat("x", 500)), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if used, max, over := s2.QuotaWarning(); over || used != 500 || max != 1000 {
		t.Fatalf("QuotaWarning() = %d, %d, %v below threshold, want 500, 1000, false", used, max, over)
	}

	if _, err := s2.Enqueue(Envelope{}, strings.NewReader(strings.Repeat("x", 300)), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if used, max, over := s2.QuotaWarning(); !over || used != 800 || max != 1000 {
		t.Fatalf("QuotaWarning() = %d, %d, %v at threshold, want 800, 1000, true", used, max, over)
	}
}

// A file the sweep could not delete must stay indexed, or its bytes stop
// counting against limits.spool_max_gb while still occupying the disk --
// which is the accounting failedIndex exists to prevent. removeRetry exists
// because this is expected on Windows, where a scanner or backup agent holds
// a handle; the directory trick below reproduces it portably.
func TestSweepFailedKeepsWhatItCouldNotDelete(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Enqueue(Envelope{Route: "r"}, strings.NewReader(strings.Repeat("x", 512)), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	meta, ok := s.Claim(time.Now().Add(time.Minute))
	if !ok {
		t.Fatal("nothing to claim")
	}
	if err := s.Fail(meta, "permanent"); err != nil {
		t.Fatal(err)
	}
	if len(s.failedIndex) != 1 {
		t.Fatalf("failedIndex holds %d entries, want 1", len(s.failedIndex))
	}
	sizeBefore := s.failedIndex[id].size

	// Replace the body with a non-empty directory of the same name: os.Remove
	// then fails with ENOTEMPTY rather than ErrNotExist, whatever the test
	// runs as.
	body := filepath.Join(dir, "spool", "failed", id.String()+".eml")
	if err := os.Remove(body); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(body, "held"), 0o700); err != nil {
		t.Fatal(err)
	}

	s.SetFailedRetention(time.Nanosecond)
	removed, freed := s.SweepFailed(time.Now().Add(time.Hour))

	if removed != 0 || freed != 0 {
		t.Errorf("SweepFailed reported removed=%d freed=%d for a message it could not delete", removed, freed)
	}
	if _, still := s.failedIndex[id]; !still {
		t.Fatal("the entry was dropped from failedIndex, so its bytes no longer count against the quota")
	}
	if s.failedIndex[id].size != sizeBefore {
		t.Errorf("indexed size changed to %d, want %d", s.failedIndex[id].size, sizeBefore)
	}

	// Once the obstruction is gone the next sweep must complete it, which is
	// the behaviour the entry was kept for.
	if err := os.RemoveAll(body); err != nil {
		t.Fatal(err)
	}
	removed, freed = s.SweepFailed(time.Now().Add(time.Hour))
	if removed != 1 {
		t.Errorf("the retried sweep removed %d, want 1", removed)
	}
	if freed != sizeBefore {
		t.Errorf("the retried sweep freed %d bytes, want %d", freed, sizeBefore)
	}
	if _, still := s.failedIndex[id]; still {
		t.Error("the entry survived a successful sweep")
	}
}

// recover drops metadata whose body is gone rather than indexing it. Without
// that, the message is not merely listed -- it is claimable, so every
// delivery attempt fails on the missing body and retries until
// queue.max_lifetime_hours expires it. That state is reachable without any
// operator mistake (a crash between the two unlinks, an interrupted removal,
// a hand-deleted spool file), and store.ReconcileRemoved exists precisely to
// clean up the history row it leaves behind.
func TestRecoverDropsMetadataWhoseBodyIsGone(t *testing.T) {
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
	if err := os.Remove(s.dataPath(id)); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, indexed := reopened.index[id]; indexed {
		t.Error("a message whose body is gone was indexed at startup")
	}
	if _, err := os.Stat(reopened.metaPath(id)); err == nil {
		t.Error("the orphaned metadata was left on disk, so the next start finds it again")
	}
	if m, ok := reopened.Claim(time.Now()); ok {
		t.Errorf("a message with no body was handed out for delivery (queue_id %s)", m.ID)
	}
}

// An interrupted stage leaves a body in spool/tmp that no metadata refers to.
// recover sweeps the directory at startup; without that they accumulate over
// every restart while counting toward no quota, so the filesystem fills up
// without limits.spool_max_gb ever firing. Staged's own comment names this
// sweep as what covers a crash before Discard.
func TestRecoverSweepsInterruptedStages(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	leftover := filepath.Join(s.tmp, "interrupted.eml")
	if err := os.WriteFile(leftover, []byte("half a message"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leftover); err == nil {
		t.Error("an interrupted stage survived a restart; they accumulate and count toward no quota")
	}
}

// obstruct replaces path with a non-empty directory of the same name, so that
// os.Remove and os.Rename fail with ENOTEMPTY rather than ErrNotExist whatever
// the test runs as. It stands in for the Windows case removeRetry exists for,
// where a scanner or a backup agent holds a handle on the file.
func obstruct(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "held"), 0o700); err != nil {
		t.Fatal(err)
	}
}

// A delivered message whose body cannot be unlinked must still lose its
// metadata. recover() drops a body with no metadata, so a stranded .eml is
// inert -- but a stranded .json beside its .eml is re-indexed at the next
// start and the message is delivered a second time. That is the whole reason
// the body is unlinked first and the metadata is unlinked even when the body
// could not be.
func TestRemoveRidesOutAHeldMetadataFile(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Enqueue(Envelope{Route: "r"}, strings.NewReader("body"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// The metadata is the file that matters: a stranded .json beside its .eml
	// is re-indexed at the next start. Obstruct it, then clear the
	// obstruction inside the retry window -- a single os.Remove gives up
	// here, and gives up before the body has been touched at all.
	meta := filepath.Join(dir, "spool", "queue", id.String()+".json")
	obstruct(t, meta)
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.RemoveAll(meta)
	}()

	if err := s.Remove(id); err != nil {
		t.Fatalf("Remove gave up on a transient obstruction: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "spool", "queue", id.String()+".eml")); !os.IsNotExist(err) {
		t.Error("the body survived a successful Remove")
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Has(id) {
		t.Error("a delivered message came back after a restart")
	}
	if n := reopened.Len(); n != 0 {
		t.Errorf("the reopened spool holds %d messages, want 0", n)
	}
}

// The operator's delete carries the same hazard from the other direction: a
// message they removed must not be delivered because the unlink lost a race.
func TestDiscardRidesOutAHeldMetadataFile(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Enqueue(Envelope{Route: "r"}, strings.NewReader("body"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(dir, "spool", "queue", id.String()+".json")
	obstruct(t, meta)
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.RemoveAll(meta)
	}()

	if err := s.Discard(id); err != nil {
		t.Fatalf("Discard gave up on a transient obstruction: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "spool", "queue", id.String()+".eml")); !os.IsNotExist(err) {
		t.Error("the body survived a successful Discard")
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Has(id) {
		t.Fatal("a message the operator deleted came back after a restart")
	}
}

// Fail moves a permanently undeliverable message aside. A rename that loses
// the same race leaves the pair in the queue directory, where the next start
// re-indexes it and the message is attempted all over again, so the rename
// retries for the reason the unlink does.
func TestFailRetriesTheRenameItCannotCompleteAtOnce(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Enqueue(Envelope{Route: "r"}, strings.NewReader("body"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	meta, ok := s.Claim(time.Now().Add(time.Minute))
	if !ok {
		t.Fatal("nothing to claim")
	}
	// Obstruct the destination, then clear it inside the retry window. A
	// single os.Rename fails outright here; renameRetry rides it out, which
	// is the difference the Windows case turns on.
	blocked := filepath.Join(dir, "spool", "failed", id.String()+".eml")
	obstruct(t, blocked)
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.RemoveAll(blocked)
	}()

	if err := s.Fail(meta, "permanent"); err != nil {
		t.Fatalf("Fail gave up on a transient obstruction: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "spool", "queue", id.String()+".eml")); !os.IsNotExist(err) {
		t.Error("the body is still in the queue directory, where the next start would re-index and retry it")
	}
	if _, err := os.Stat(blocked); err != nil {
		t.Errorf("the body did not arrive in spool/failed: %v", err)
	}
}

// Claim promises the oldest due message, and the dispatcher relies on it:
// that ordering is the only thing keeping a message from starving behind
// younger ones on a busy route. Nothing tested it until Claim stopped
// sorting, which is when a reversed comparison would have become silent.
func TestClaimReturnsTheOldestDueMessage(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	// Enqueued youngest first, so insertion order cannot stand in for the
	// answer and neither can map iteration order.
	want := make([]ID, 3)
	for i, age := range []time.Duration{0, time.Minute, 2 * time.Minute} {
		env := Envelope{From: "a@example.at", To: []string{"b@example.net"},
			Client: "c", Route: "r", Received: base.Add(-age)}
		id, err := s.Enqueue(env, strings.NewReader("body\r\n"), 0, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		want[len(want)-1-i] = id
	}

	for i, expect := range want {
		m, ok := s.Claim(time.Now())
		if !ok {
			t.Fatalf("claim %d: queue reported empty with %d left", i, len(want)-i)
		}
		if m.ID != expect {
			t.Fatalf("claim %d returned %s, want %s (out of order)", i, m.ID, expect)
		}
	}
}

// Defer is the in-memory half of the scheduling: it must reschedule without
// writing, because the dispatcher calls it for every message queued behind a
// saturated route on every poll, and Release's fsync there is what made a
// hanging smarthost expensive for the whole spool.
func TestDeferReschedulesWithoutWritingMetadata(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{From: "a@example.at", To: []string{"b@example.net"},
		Client: "c", Route: "r", Received: time.Now().UTC()}
	id, err := s.Enqueue(env, strings.NewReader("body\r\n"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	meta, ok := s.Claim(time.Now())
	if !ok {
		t.Fatal("nothing to claim")
	}
	metaPath := filepath.Join(dir, "spool", "queue", id.String()+".json")
	before, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}

	until := time.Now().Add(time.Minute)
	s.Defer(meta, until)

	after, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("Defer wrote the metadata file; that is Release's job")
	}
	if _, ok := s.Claim(time.Now()); ok {
		t.Error("a deferred message was handed out again straight away")
	}
	got, ok := s.Claim(until.Add(time.Second))
	if !ok {
		t.Fatal("the message never came back after its deferral ran out")
	}
	if got.ID != id {
		t.Fatalf("claimed %s, want %s", got.ID, id)
	}
}

// Requeue leases the message for the duration of its file operations instead
// of holding the spool mutex across them (2026-09-18). Concurrent requeues of
// one failed message must therefore still resolve to exactly one requeue:
// every caller either succeeds or is told ErrBusy, the body ends up in the
// queue once, and nothing is left behind in spool/failed.
func TestConcurrentRequeueResolvesToOne(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := enqueueAndFail(t, s, "Subject: x\r\n\r\nbody\r\n")

	const callers = 8
	var wg sync.WaitGroup
	results := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- s.Requeue(id)
		}()
	}
	wg.Wait()
	close(results)

	ok, busy := 0, 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrBusy):
			busy++
		default:
			t.Errorf("unexpected Requeue error: %v", err)
		}
	}
	if ok == 0 {
		t.Fatalf("every one of %d concurrent requeues was refused", callers)
	}
	if ok+busy != callers {
		t.Fatalf("%d ok + %d busy != %d callers", ok, busy, callers)
	}

	if _, err := os.Stat(filepath.Join(s.failed, id.String()+".eml")); !os.IsNotExist(err) {
		t.Errorf("the body is still in spool/failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.failed, id.String()+".json")); !os.IsNotExist(err) {
		t.Errorf("the metadata is still in spool/failed: %v", err)
	}
	m, claimed := s.Claim(time.Now())
	if !claimed || m.ID != id {
		t.Fatalf("the requeued message is not claimable: %v %v", m, claimed)
	}
	if m.Attempts != 0 {
		t.Errorf("Attempts = %d after a requeue, want 0", m.Attempts)
	}
	if _, again := s.Claim(time.Now()); again {
		t.Error("the message was requeued more than once")
	}
}

// ClaimBatch returns the globally oldest due messages, not the first max it
// happens to walk past: the index is a map, so iteration order is random and
// a bounded scan that kept the wrong end of it would starve the oldest mail
// in the queue -- which is the one an operator is waiting on.
func TestClaimBatchReturnsTheGloballyOldest(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	want := make([]ID, 0, 5)
	for i := 0; i < 50; i++ {
		env := Envelope{From: "a@example.at", To: []string{"b@example.net"}, Client: "c", Route: "r",
			Received: base.Add(time.Duration(i) * time.Minute)}
		id, err := s.Enqueue(env, strings.NewReader("body"), 0, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if i < 5 {
			want = append(want, id)
		}
	}

	got := s.ClaimBatch(time.Now(), 5, nil)
	if len(got) != 5 {
		t.Fatalf("ClaimBatch returned %d messages, want 5", len(got))
	}
	for i, m := range got {
		if m.ID != want[i] {
			t.Fatalf("position %d is %s, want %s: the batch is not the oldest five in order", i, m.ID, want[i])
		}
	}
	for _, m := range got {
		if !s.leasedFor(m.ID) {
			t.Fatalf("%s was returned but not leased", m.ID)
		}
	}
}

// skip is what keeps a tick from re-scanning the whole index once per message
// queued behind a saturated route.
func TestClaimBatchHonoursSkip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, route := range []string{"busy", "free"} {
		env := Envelope{From: "a@example.at", To: []string{"b@example.net"}, Client: "c",
			Route: route, Received: now}
		if _, err := s.Enqueue(env, strings.NewReader("body"), 0, time.Hour); err != nil {
			t.Fatal(err)
		}
	}

	got := s.ClaimBatch(time.Now(), 10, func(route string) bool { return route == "busy" })
	if len(got) != 1 {
		t.Fatalf("ClaimBatch returned %d messages, want 1", len(got))
	}
	if got[0].Envelope.Route != "free" {
		t.Fatalf("returned a message for route %q, want the one route skip allowed", got[0].Envelope.Route)
	}
}

// A max of zero or less asks for nothing and must lease nothing, rather than
// falling through to "everything".
func TestClaimBatchRefusesANonPositiveMax(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	enqueueOneForTest(t, s)
	if got := s.ClaimBatch(time.Now(), 0, nil); got != nil {
		t.Fatalf("ClaimBatch(max=0) returned %d messages", len(got))
	}
	if _, ok := s.Claim(time.Now()); !ok {
		t.Fatal("the message was leased by a batch that asked for none")
	}
}

// Commit reserves against the quota rather than only checking it: two
// commits that each fit alone must not both be admitted when together they
// do not, which is what a check followed by a write allows.
func TestConcurrentCommitsCannotOvershootTheQuota(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const body = 4096
	// Room for four bodies, against eight concurrent commits.
	s.mu.Lock()
	s.maxQuotaBytes = 4 * body
	s.mu.Unlock()

	env := Envelope{From: "a@example.at", To: []string{"b@example.net"}, Client: "c", Route: "r",
		Received: time.Now().UTC()}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.Enqueue(env, strings.NewReader(strings.Repeat("x", body)), 0, time.Hour)
		}()
	}
	wg.Wait()

	if used := s.spoolSize(); used > 4*body {
		t.Fatalf("the spool holds %d bytes against a quota of %d", used, 4*body)
	}
}

// leasedFor and enqueueOneForTest keep the assertions above off the spool's
// internals beyond the one lock they have to take.
func (s *Spool) leasedFor(id ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leased[id]
}

func enqueueOneForTest(t *testing.T, s *Spool) ID {
	t.Helper()
	env := Envelope{From: "a@example.at", To: []string{"b@example.net"}, Client: "c", Route: "r",
		Received: time.Now().UTC()}
	id, err := s.Enqueue(env, strings.NewReader("body"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// The dashboard sidebar, the API's health and routes endpoints and the
// metrics exposition all read the depth, and each read used to walk the whole
// index while holding the mutex that Commit, ClaimBatch, Remove and Defer
// take -- 179ms at a million queued messages, per page view. How often mail
// intake paused was therefore set by how many people were watching.
func TestQueueDepthServesRepeatedReadsFromCache(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{From: "a@example.at", To: []string{"b@example.net"},
		Client: "c", Route: "r", Received: time.Now().UTC()}
	if _, err := s.Enqueue(env, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}

	// A moment after both enqueues, so every message counts as claimable.
	// Reading "now" from before them made an added message count as deferred
	// -- its NextAttempt is the instant it was committed -- and the queued
	// figure then stayed at 1 whether the cache was used or not, which is a
	// test that passes for the wrong reason.
	now := time.Now().Add(time.Minute)
	first := s.QueueDepth(now)
	if first["r"].Queued != 1 {
		t.Fatalf("first read reported %d queued, want 1", first["r"].Queued)
	}

	// A second message inside the window is not expected to show yet: the
	// staleness is the point, and asserting it here is what stops the cache
	// from being quietly removed again.
	if _, err := s.Enqueue(env, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	if again := s.QueueDepth(now); again["r"].Queued != 1 {
		t.Errorf("a read inside the cache window rescanned the index (reported %d)", again["r"].Queued)
	}

	// Past the window the index is read again. depthCacheFloor is the
	// shortest window, so stepping past it is enough whatever the scan cost.
	later := now.Add(depthCacheFloor + time.Second)
	if fresh := s.QueueDepth(later); fresh["r"].Queued != 2 {
		t.Errorf("after the cache window the depth is still %d, want 2", fresh["r"].Queued)
	}
}

// The split is a function of the moment asked about, so a caller asking about
// a different moment must never be served the cached answer -- which is how
// the deferred half is tested everywhere else in this file.
func TestQueueDepthDoesNotServeADifferentMomentFromCache(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{From: "a@example.at", To: []string{"b@example.net"},
		Client: "c", Route: "r", Received: time.Now().UTC()}
	id, err := s.Enqueue(env, strings.NewReader("x"), 0, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := s.Claim(time.Now())
	if !ok {
		t.Fatal("nothing to claim")
	}
	m.NextAttempt = time.Now().Add(6 * time.Hour)
	if err := s.Release(m); err != nil {
		t.Fatal(err)
	}
	_ = id

	now := time.Now()
	if d := s.QueueDepth(now)["r"]; d.Deferred != 1 {
		t.Fatalf("now: deferred %d, want 1", d.Deferred)
	}
	// Reaching past the deferral, immediately: same wall clock, different
	// question. A cache keyed only on elapsed time would answer "deferred".
	if d := s.QueueDepth(now.Add(12 * time.Hour))["r"]; d.Queued != 1 {
		t.Errorf("a later moment was answered from the cache: queued %d, want 1", d.Queued)
	}
}

// The caller gets a copy: writing into the returned map must not corrupt what
// the next reader is served.
func TestQueueDepthReturnsACopy(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{From: "a@example.at", To: []string{"b@example.net"},
		Client: "c", Route: "r", Received: time.Now().UTC()}
	if _, err := s.Enqueue(env, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	// Both return paths hand out a map, and both have to copy: the fresh
	// scan and the cache hit. Writing into only the first leaves the second
	// uncovered, and the second is the one that hands out the cache itself.
	now := time.Now().Add(time.Minute)

	fresh := s.QueueDepth(now) // scans
	fresh["r"] = RouteDepth{Queued: 98}
	if after := s.QueueDepth(now)["r"]; after.Queued != 1 {
		t.Fatalf("writing into a freshly scanned result reached the cache: queued %d, want 1", after.Queued)
	}

	cached := s.QueueDepth(now) // served from the cache
	cached["r"] = RouteDepth{Queued: 99}
	if after := s.QueueDepth(now)["r"]; after.Queued != 1 {
		t.Errorf("writing into a cached result reached the cache: queued %d, want 1", after.Queued)
	}
}

// recover answers "does this message have a body" from the directory listing
// it already read, not with a stat per message. The behaviour that has to
// survive that change is what this pins: metadata without a body is dropped,
// a body without usable metadata is dropped, and a complete pair is indexed.
func TestRecoverHandlesEveryHalfPairFromOneListing(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{From: "a@example.at", To: []string{"b@example.net"},
		Client: "c", Route: "r", Received: time.Now().UTC()}
	whole, err := s.Enqueue(env, strings.NewReader("body\r\n"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	orphanMeta, err := s.Enqueue(env, strings.NewReader("body\r\n"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	orphanBody, err := s.Enqueue(env, strings.NewReader("body\r\n"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	queue := filepath.Join(dir, "spool", "queue")
	// One message loses its body, one loses its metadata, and one file is
	// left behind whose name is not a queue id at all.
	if err := os.Remove(filepath.Join(queue, orphanMeta.String()+".eml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(queue, orphanBody.String()+".json")); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(queue, "not-a-queue-id.eml")
	if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 1 {
		t.Fatalf("recovered %d messages, want only the complete one", s2.Len())
	}
	if !s2.Has(whole) {
		t.Error("the complete message was not recovered")
	}
	for name, path := range map[string]string{
		"metadata without a body":       filepath.Join(queue, orphanMeta.String()+".json"),
		"body without metadata":         filepath.Join(queue, orphanBody.String()+".eml"),
		"a file that is not a queue id": stray,
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s survived recovery: %v", name, err)
		}
	}
	// And the complete pair is untouched.
	for _, ext := range []string{".json", ".eml"} {
		if _, err := os.Stat(filepath.Join(queue, whole.String()+ext)); err != nil {
			t.Errorf("the complete message lost its %s: %v", ext, err)
		}
	}
}

// Metadata that will not parse is not a message: its body has to go too, or
// it sits in the spool forever counting against the quota.
func TestRecoverDropsAPairWhoseMetadataIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{From: "a@example.at", To: []string{"b@example.net"},
		Client: "c", Route: "r", Received: time.Now().UTC()}
	id, err := s.Enqueue(env, strings.NewReader("body\r\n"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	queue := filepath.Join(dir, "spool", "queue")
	if err := os.WriteFile(filepath.Join(queue, id.String()+".json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 0 {
		t.Errorf("a message with unparsable metadata was recovered")
	}
	if _, err := os.Stat(filepath.Join(queue, id.String()+".eml")); !os.IsNotExist(err) {
		t.Errorf("its body survived: %v", err)
	}
}

// The queue directory is read in batches, so a spool holding more than one
// batch is the only thing that exercises the loop. A break after the first
// batch would silently lose every message past recoverBatch on restart --
// mail the sender was told had been accepted.
func TestRecoverReadsEveryBatch(t *testing.T) {
	dir := t.TempDir()
	queue := filepath.Join(dir, "spool", "queue")
	if err := os.MkdirAll(queue, 0o700); err != nil {
		t.Fatal(err)
	}

	// Written directly rather than through Enqueue: this is about the
	// directory loop, and Enqueue's three fsyncs per message would make a
	// batch-and-a-bit take minutes.
	const n = recoverBatch + 17
	base := time.Now().UTC().Add(-time.Hour)
	body := []byte("Subject: x\r\n\r\nbody\r\n")
	for i := 0; i < n; i++ {
		id := loadIDForTest(i)
		m := Meta{
			ID: id, NextAttempt: base, Expires: base.Add(96 * time.Hour),
			Envelope: Envelope{From: "a@example.at", To: []string{"b@example.net"},
				Client: "c", Route: "r", Received: base},
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(queue, id.String()+".json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(queue, id.String()+".eml"), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != n {
		t.Fatalf("recovered %d of %d messages; the directory loop stopped early", s.Len(), n)
	}
	// And the last one, which only the final batch can have reached.
	if !s.Has(loadIDForTest(n - 1)) {
		t.Error("the last message of the last batch was not recovered")
	}
}

// loadIDForTest builds a queue id from a counter, in the alphabet ParseID
// accepts. Ids outside it are skipped by recover, which would make the test
// above pass for the wrong reason.
func loadIDForTest(i int) ID {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var b [16]byte
	for k := 0; k < 16; k++ {
		b[k] = alphabet[(i>>(5*k))&31]
	}
	return ID(b[:])
}
