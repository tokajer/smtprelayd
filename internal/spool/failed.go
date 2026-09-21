// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package spool

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// failedStore is the mirror of the spool/failed directory: what each message
// kept there costs, when it landed, and how long it may stay.
//
// A type with a lock of its own, because it shares no invariant with the live
// queue. Nothing here may ever be claimed, leased or delivered, so it needs
// none of the guarantees Spool.mu provides -- and a permanently failed message
// leaves the live index without leaving the disk, so a quota that summed only
// that index would let a client which reliably fails free its own quota while
// still occupying the filesystem the quota exists to protect.
//
// Until 2026-09-21 this was four fields on Spool behind a failedMu, which
// meant every Spool method could reach it and the rule that its lock is never
// held while another is taken was a comment rather than a property of the call
// graph. Both accounting defects fixed that day were cross-index mistakes,
// which is the failure that shape permits.
type failedStore struct {
	// dir is spool/failed. Owned here because reindex and sweep are entirely
	// about that directory; the Spool methods that move files into or out of
	// it reach the path through this field.
	dir string

	mu    sync.Mutex
	index map[ID]failedEntry
	bytes int64
	ttl   time.Duration
}

func newFailedStore(dir string) *failedStore {
	return &failedStore{dir: dir, index: map[ID]failedEntry{}}
}

// path is the name of one of a failed message's two files.
func (f *failedStore) path(id ID, ext string) string {
	return filepath.Join(f.dir, id.String()+ext)
}

// put records a message now sitting in spool/failed.
func (f *failedStore) put(id ID, e failedEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if old, ok := f.index[id]; ok {
		f.bytes -= old.size
	}
	f.index[id] = e
	f.bytes += e.size
}

// drop removes a message from the mirror, reporting what it had been costing.
func (f *failedStore) drop(id ID) (failedEntry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.index[id]
	if ok {
		f.bytes -= e.size
		delete(f.index, id)
	}
	return e, ok
}

// has reports whether spool/failed still holds this message.
func (f *failedStore) has(id ID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.index[id]
	return ok
}

// occupied is what these messages cost on disk, for the quota.
func (f *failedStore) occupied() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bytes
}

// setRetention configures how long a permanently failed message's files are
// kept. Zero disables the sweep.
func (f *failedStore) setRetention(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ttl = d
}

// reindex accounts for what is already sitting in spool/failed at startup.
// Unlike the queue sweep in recover, nothing here is removed or repaired:
// these messages are kept deliberately, and the operator's requeue action is
// the only thing that should resurrect one. This only makes them visible to
// the quota and to the retention sweep.
func (f *failedStore) reindex() error {
	entries, err := os.ReadDir(f.dir)
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
		if fi, err := os.Stat(f.path(id, ".eml")); err == nil {
			size = fi.Size()
		}
		// The body's own size, not Envelope.Size: what the quota is about is
		// what the filesystem is holding, and the two differ by the per-copy
		// Received header Commit prepends.
		//
		// The body alone, not the body plus info.Size(): the live index counts
		// Envelope.Size, which is the body and nothing else, so counting the
		// metadata file here made a message grow by a few hundred bytes as it
		// moved from queued to failed and left usedBytes summing two different
		// definitions of what the spool occupies. Both now mean "the bodies",
		// which understates the total by one metadata file per message -- a
		// known, uniform few hundred bytes against a ceiling in gigabytes.
		f.put(id, failedEntry{size: size, at: info.ModTime()})
	}
	return nil
}

// sweep deletes messages that have been sitting in spool/failed for longer
// than the configured retention, freeing both the disk and the quota they
// hold. Their history rows are untouched: what a failure was and what the
// smarthost said about it outlives the copy of the message itself, and
// history.retention_days governs that separately.
//
// Returns the number of messages removed and the bytes freed. A retention of
// zero disables the sweep, which keeps every failure forever -- the behaviour
// before this existed, still reachable deliberately rather than by omission.
func (f *failedStore) sweep(now time.Time) (removed int, freed int64) {
	f.mu.Lock()
	ttl := f.ttl
	if ttl <= 0 {
		f.mu.Unlock()
		return 0, 0
	}
	var expired []ID
	for id, e := range f.index {
		if now.Sub(e.at) > ttl {
			expired = append(expired, id)
		}
	}
	f.mu.Unlock()

	for _, id := range expired {
		// Tracked across both extensions rather than acted on inside the
		// loop: a "continue" there only advances to the next extension, so
		// the accounting below ran even when nothing had been deleted --
		// dropping the entry from the index, reporting its bytes as freed,
		// and leaving the files occupying the disk untracked by the quota
		// until the next restart re-read the directory. removeRetry exists
		// precisely because this failure is expected on Windows.
		gone := true
		for _, ext := range []string{".json", ".eml"} {
			if err := removeRetry(f.path(id, ext)); err != nil && !os.IsNotExist(err) {
				gone = false
			}
		}
		if !gone {
			// Leave it indexed so the next sweep tries again rather than
			// losing track of bytes that are still on the disk.
			continue
		}
		if e, still := f.drop(id); still {
			removed++
			freed += e.size
		}
	}
	if removed > 0 {
		_ = syncDir(f.dir)
	}
	return removed, freed
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
		dst := s.failed.path(m.ID, ext)
		// The body only, matching both the live index and reindex; see
		// the note there on why the metadata file is left out of all three.
		if ext == ".eml" {
			if fi, err := os.Stat(src); err == nil {
				onDisk = fi.Size()
			}
		}
		if err := renameRetry(src, dst); err != nil && !os.IsNotExist(err) {
			// Recorded, not returned: the message has already left the live
			// index, so returning here would leave whichever half did move
			// sitting in spool/failed charged to nobody -- the quota would
			// lose those bytes until a restart re-read the directory, which
			// is precisely the accounting failedStore exists to keep. The
			// entry is written below for what is actually there, and the
			// error is reported afterwards.
			if moveErr == nil {
				moveErr = err
			}
		}
	}
	// Still counted against the quota, from the other index. The message left
	// the queue; it did not leave the disk.
	s.failed.put(m.ID, failedEntry{size: onDisk, at: time.Now()})

	if moveErr != nil {
		return moveErr
	}
	return syncDir(s.failed.dir)
}

// SweepFailed deletes messages whose retention has run out; see
// failedStore.sweep, which does the work.
func (s *Spool) SweepFailed(now time.Time) (removed int, freed int64) {
	return s.failed.sweep(now)
}

// SetFailedRetention configures how long spool/failed keeps a permanently
// failed message's files. Zero disables the sweep.
func (s *Spool) SetFailedRetention(d time.Duration) { s.failed.setRetention(d) }
