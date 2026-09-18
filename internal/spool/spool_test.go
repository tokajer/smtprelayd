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
