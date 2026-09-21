// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package spool

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// spool/failed: what a permanently failed message costs on disk, how it gets
// there, and when it leaves. Nothing here is ever claimed or delivered; the
// operator's Requeue in spool.go is the only way back.

// failedEntry is the little that is needed about a message in spool/failed:
// what it costs on disk, and when it landed there. The timestamp is the
// metadata file's modification time, which Fail sets by writing the file
// immediately before the rename -- so it needs no new persisted field and is
// correct for messages that failed under an earlier version.
type failedEntry struct {
	size int64
	at   time.Time
}

// indexFailed accounts for what is already sitting in spool/failed at startup.
// Unlike the queue sweep above, nothing here is removed or repaired: these
// messages are kept deliberately, and the operator's requeue action is the
// only thing that should resurrect one. This only makes them visible to the
// quota and to the retention sweep.
func (s *Spool) indexFailed() error {
	entries, err := os.ReadDir(s.failed)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id, err := ParseID(strings.TrimSuffix(name, ".json"))
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		size := int64(0)
		if fi, err := os.Stat(filepath.Join(s.failed, id.String()+".eml")); err == nil {
			size = fi.Size()
		}
		// The body's own size, not Envelope.Size: what the quota is about is
		// what the filesystem is holding, and the two differ by the per-copy
		// Received header Commit prepends.
		s.putFailed(id, failedEntry{size: size + info.Size(), at: info.ModTime()})
	}
	return nil
}

// renameRetry moves a path, retrying briefly, for the reason given on
// removeRetry: on Windows a handle held by a scanner or a backup agent makes
// this fail with a sharing violation rather than with a missing file.
func renameRetry(src, dst string) error {
	var err error
	for i := 0; i < 5; i++ {
		if err = os.Rename(src, dst); err == nil || os.IsNotExist(err) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return err
}

// Fail moves a permanently undeliverable message aside. Phase 5 turns these
// into DSNs; until then they are kept so that nothing is silently lost.
func (s *Spool) Fail(m *Meta, reason string) error {
	m.LastError = reason
	if err := s.writeMeta(m); err != nil {
		return err
	}
	s.mu.Lock()
	s.dropLocked(m.ID)
	delete(s.leased, m.ID)
	s.mu.Unlock()

	var onDisk int64
	var moveErr error
	// Through renameRetry for the reason removeRetry exists: a rename that
	// loses the race against a scanner's handle leaves the pair sitting in
	// the queue directory, where the next start re-indexes it and a message
	// that failed permanently is attempted all over again.
	for _, ext := range []string{".json", ".eml"} {
		src := filepath.Join(s.queue, m.ID.String()+ext)
		dst := filepath.Join(s.failed, m.ID.String()+ext)
		if fi, err := os.Stat(src); err == nil {
			onDisk += fi.Size()
		}
		if err := renameRetry(src, dst); err != nil && !os.IsNotExist(err) {
			// Recorded, not returned: the message has already left the live
			// index, so returning here would leave whichever half did move
			// sitting in spool/failed charged to nobody -- the quota would
			// lose those bytes until a restart re-read the directory, which
			// is precisely the accounting failedIndex exists to keep. The
			// entry is written below for what is actually there, and the
			// error is reported afterwards.
			if moveErr == nil {
				moveErr = err
			}
		}
	}
	// Still counted against the quota, from the other index. The message left
	// the queue; it did not leave the disk.
	s.putFailed(m.ID, failedEntry{size: onDisk, at: time.Now()})

	if moveErr != nil {
		return moveErr
	}
	return syncDir(s.failed)
}

// SweepFailed deletes messages that have been sitting in spool/failed for
// longer than the configured retention, freeing both the disk and the quota
// they hold. Their history rows are untouched: what a failure was and what the
// smarthost said about it outlives the copy of the message itself, and
// history.retention_days governs that separately.
//
// Returns the number of messages removed and the bytes freed. A retention of
// zero disables the sweep, which keeps every failure forever -- the behaviour
// before this existed, still reachable deliberately rather than by omission.
func (s *Spool) SweepFailed(now time.Time) (removed int, freed int64) {
	s.failedMu.Lock()
	ttl := s.failedTTL
	if ttl <= 0 {
		s.failedMu.Unlock()
		return 0, 0
	}
	var expired []ID
	for id, e := range s.failedIndex {
		if now.Sub(e.at) > ttl {
			expired = append(expired, id)
		}
	}
	s.failedMu.Unlock()

	for _, id := range expired {
		// Tracked across both extensions rather than acted on inside the
		// loop: a "continue" there only advances to the next extension, so
		// the accounting below ran even when nothing had been deleted --
		// dropping the entry from failedIndex, reporting its bytes as freed,
		// and leaving the files occupying the disk untracked by the quota
		// until the next restart re-read the directory. removeRetry exists
		// precisely because this failure is expected on Windows.
		gone := true
		for _, ext := range []string{".json", ".eml"} {
			if err := removeRetry(filepath.Join(s.failed, id.String()+ext)); err != nil && !os.IsNotExist(err) {
				gone = false
			}
		}
		if !gone {
			// Leave it indexed so the next sweep tries again rather than
			// losing track of bytes that are still on the disk.
			continue
		}
		if e, still := s.dropFailed(id); still {
			removed++
			freed += e.size
		}
	}
	if removed > 0 {
		_ = syncDir(s.failed)
	}
	return removed, freed
}

// SetFailedRetention configures how long spool/failed keeps a permanently
// failed message's files. Zero disables the sweep.
func (s *Spool) SetFailedRetention(d time.Duration) {
	s.failedMu.Lock()
	defer s.failedMu.Unlock()
	s.failedTTL = d
}
