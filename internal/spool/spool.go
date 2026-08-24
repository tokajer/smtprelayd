// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package spool provides the durable on-disk message queue.
package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Envelope is everything known about a message at the moment it was accepted.
type Envelope struct {
	From       string    `json:"from"`
	To         []string  `json:"to"`
	Client     string    `json:"client"`
	Route      string    `json:"route"`
	Listener   string    `json:"listener"`
	RemoteAddr string    `json:"remote_addr"`
	Helo       string    `json:"helo"`
	TLS        bool      `json:"tls"`
	Size       int64     `json:"size"`
	Received   time.Time `json:"received"`

	// OriginalFrom is the envelope sender the client declared, present only
	// when rewriting replaced it. A bounce record needs both values.
	OriginalFrom string `json:"original_from,omitempty"`

	// Notification marks a message the bounce notifier composed itself
	// rather than one accepted from a client. It never goes through the
	// listener, so it is never subject to sender rewriting by construction;
	// this flag exists only so the delivery manager can recognise one on a
	// later attempt (including after a restart, since it is persisted here)
	// and refuse to let its own failure enqueue another notification, which
	// is how a notification loop would start. Absent on every message a
	// listener ever wrote, so decoding an older meta file defaults it to
	// false.
	Notification bool `json:"notification,omitempty"`

	// Canary marks a message the canary runner composed itself: diagnostic
	// traffic, not a client's. Kept separate from Notification because the
	// two must diverge in the delivery manager -- a canary's outcome still
	// belongs in the bounce digest (RecordFail gates on Notification alone,
	// so leaving this true would silently opt a failing canary out of the
	// alerting it exists to feed), but like Notification it must stay out of
	// its route's own delivered/bounced/deferred counters, which describe
	// client traffic and would otherwise be muddied by a probe.
	Canary bool `json:"canary,omitempty"`
}

// Meta is the persisted state of a queued message.
type Meta struct {
	ID          ID        `json:"id"`
	Envelope    Envelope  `json:"envelope"`
	Attempts    int       `json:"attempts"`
	LastError   string    `json:"last_error,omitempty"`
	NextAttempt time.Time `json:"next_attempt"`
	Expires     time.Time `json:"expires"`
}

// ErrTooLarge is returned when a message exceeds the caller's byte budget.
var ErrTooLarge = errors.New("spool: message exceeds size limit")

// ErrNotFound is returned for an unknown queue ID.
var ErrNotFound = errors.New("spool: message not found")

// ErrQuotaExceeded is returned when the spool has exceeded its maximum size.
var ErrQuotaExceeded = errors.New("spool: quota exceeded")

// Spool is a crash-safe queue backed by a directory. A message is only
// visible once its metadata file has been renamed into place, so a crash
// halfway through an enqueue leaves rubbish in tmp and nothing in the queue.
type Spool struct {
	root   string
	tmp    string
	queue  string
	failed string

	mu     sync.Mutex
	index  map[ID]*Meta
	leased map[ID]bool

	// failed mirrors spool/failed. A permanently failed message leaves the
	// live index but not the disk, so a quota that summed only index would
	// let a client which reliably fails free its own quota while continuing
	// to occupy the filesystem. Kept as a separate map rather than folded
	// into index because nothing may ever claim, lease or deliver these.
	failedIndex map[ID]failedEntry

	maxQuotaBytes    int64
	warnQuotaPercent int
	failedTTL        time.Duration
}

// failedEntry is the little that is needed about a message in spool/failed:
// what it costs on disk, and when it landed there. The timestamp is the
// metadata file's modification time, which Fail sets by writing the file
// immediately before the rename -- so it needs no new persisted field and is
// correct for messages that failed under an earlier version.
type failedEntry struct {
	size int64
	at   time.Time
}

// Open prepares the spool directories and recovers any prior state.
func Open(dataDir string) (*Spool, error) {
	s := &Spool{
		root:        dataDir,
		tmp:         filepath.Join(dataDir, "spool", "tmp"),
		queue:       filepath.Join(dataDir, "spool", "queue"),
		failed:      filepath.Join(dataDir, "spool", "failed"),
		index:       map[ID]*Meta{},
		leased:      map[ID]bool{},
		failedIndex: map[ID]failedEntry{},
	}
	for _, d := range []string{s.tmp, s.queue, s.failed} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := ensureMode(d); err != nil {
			return nil, err
		}
	}
	if err := s.recover(); err != nil {
		return nil, err
	}
	return s, nil
}

// recover discards partial enqueues and rebuilds the in-memory index.
func (s *Spool) recover() error {
	entries, err := os.ReadDir(s.tmp)
	if err != nil {
		return err
	}
	for _, e := range entries {
		_ = os.Remove(filepath.Join(s.tmp, e.Name()))
	}

	entries, err = os.ReadDir(s.queue)
	if err != nil {
		return err
	}
	seen := map[ID]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		id, err := ParseID(strings.TrimSuffix(name, ".json"))
		if err != nil {
			continue
		}
		m, err := s.readMeta(id)
		if err != nil {
			continue
		}
		if _, err := os.Stat(s.dataPath(id)); err != nil {
			// Metadata without a body cannot be delivered and cannot be
			// bounced meaningfully; drop it rather than retry forever.
			_ = os.Remove(s.metaPath(id))
			continue
		}
		s.index[id] = m
		seen[id] = true
	}

	// A body without metadata is an interrupted enqueue: the sender was never
	// told the message was accepted, so removing it loses nothing.
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".eml") {
			continue
		}
		id, err := ParseID(strings.TrimSuffix(name, ".eml"))
		if err != nil || !seen[id] {
			_ = os.Remove(filepath.Join(s.queue, name))
		}
	}

	return s.indexFailed()
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
		s.failedIndex[id] = failedEntry{size: size + info.Size(), at: info.ModTime()}
	}
	return nil
}

func (s *Spool) metaPath(id ID) string { return filepath.Join(s.queue, id.String()+".json") }
func (s *Spool) dataPath(id ID) string { return filepath.Join(s.queue, id.String()+".eml") }

// Staged is a message body written to the spool's temporary area so that it
// can be committed once per route without being read from the client twice.
// It must be discarded when it is no longer needed; a crash before that is
// covered by the tmp sweep in recover.
type Staged struct {
	path string
	size int64
}

// Size is the number of octets staged, excluding any per-copy prefix.
func (st *Staged) Size() int64 { return st.size }

// Discard removes the staged body. It is idempotent and safe to defer.
func (st *Staged) Discard() {
	if st == nil || st.path == "" {
		return
	}
	_ = os.Remove(st.path)
	st.path = ""
}

// Stage streams a message body to disk. maxBytes of zero means no limit
// beyond the caller's own enforcement.
func (s *Spool) Stage(body io.Reader, maxBytes int64) (*Staged, error) {
	id, err := NewID()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(s.tmp, id.String()+".staged")
	//#nosec G304 -- path is s.tmp joined with a freshly generated, validated ID; O_NOFOLLOW and O_EXCL close the symlink and pre-creation races
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|noFollow, 0o600)
	if err != nil {
		return nil, err
	}
	var n int64
	if maxBytes > 0 {
		n, err = io.Copy(f, io.LimitReader(body, maxBytes+1))
		if err == nil && n > maxBytes {
			err = ErrTooLarge
		}
	} else {
		n, err = io.Copy(f, body)
	}
	if err == nil {
		err = f.Sync()
	}
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return &Staged{path: path, size: n}, nil
}

// Commit makes one copy of a staged body visible as a queued message. prefix,
// if non-nil, produces the octets written ahead of the body; it receives the
// queue ID so that a Received header can name the copy it belongs to. The
// prefix is why each copy is written rather than renamed: prepending to an
// existing file is not cheaper than copying it.
func (s *Spool) Commit(st *Staged, env Envelope, lifetime time.Duration, prefix func(ID) string) (ID, error) {
	if st == nil || st.path == "" {
		return "", errors.New("spool: commit of a discarded stage")
	}

	if s.maxQuotaBytes > 0 && s.spoolSize()+st.size > s.maxQuotaBytes {
		return "", ErrQuotaExceeded
	}

	id, err := NewID()
	if err != nil {
		return "", err
	}

	src, err := os.OpenFile(st.path, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return "", err
	}
	defer src.Close()

	tmpData := filepath.Join(s.tmp, id.String()+".eml")
	//#nosec G304 -- tmpData is s.tmp joined with a validated ID; see Stage for the O_NOFOLLOW/O_EXCL reasoning
	dst, err := os.OpenFile(tmpData, os.O_CREATE|os.O_EXCL|os.O_WRONLY|noFollow, 0o600)
	if err != nil {
		return "", err
	}
	var n int64
	if prefix != nil {
		if head := prefix(id); head != "" {
			var written int
			written, err = dst.WriteString(head)
			n += int64(written)
		}
	}
	if err == nil {
		var copied int64
		copied, err = io.Copy(dst, src)
		n += copied
	}
	if err == nil {
		err = dst.Sync()
	}
	cerr := dst.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmpData)
		return "", err
	}

	env.Size = n
	now := time.Now().UTC()
	m := &Meta{
		ID:          id,
		Envelope:    env,
		NextAttempt: now,
		Expires:     now.Add(lifetime),
	}

	if err := os.Rename(tmpData, s.dataPath(id)); err != nil {
		_ = os.Remove(tmpData)
		return "", err
	}
	if err := s.writeMeta(m); err != nil {
		_ = os.Remove(s.dataPath(id))
		return "", err
	}
	if err := syncDir(s.queue); err != nil {
		return "", err
	}

	s.mu.Lock()
	s.index[id] = m
	s.mu.Unlock()
	return id, nil
}

// Enqueue stages and commits a single copy. It is the path used by callers
// that deliver a message to exactly one route.
func (s *Spool) Enqueue(env Envelope, body io.Reader, maxBytes int64, lifetime time.Duration) (ID, error) {
	st, err := s.Stage(body, maxBytes)
	if err != nil {
		return "", err
	}
	defer st.Discard()
	return s.Commit(st, env, lifetime, nil)
}

// writeMeta replaces the metadata file atomically.
func (s *Spool) writeMeta(m *Meta) error {
	if !m.ID.valid() {
		return ErrInvalidID
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.tmp, m.ID.String()+".json")
	//#nosec G304 -- tmp is s.tmp joined with a validated ID; see Stage for the O_NOFOLLOW/O_EXCL reasoning
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|noFollow, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, s.metaPath(m.ID))
}

func (s *Spool) readMeta(id ID) (*Meta, error) {
	if !id.valid() {
		return nil, ErrInvalidID
	}
	b, err := os.ReadFile(s.metaPath(id))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.ID != id {
		return nil, fmt.Errorf("spool: metadata for %s claims id %s", id, m.ID)
	}
	return &m, nil
}

// Open returns the message body for reading.
func (s *Spool) Open(id ID) (*os.File, error) {
	if !id.valid() {
		return nil, ErrInvalidID
	}
	return os.OpenFile(s.dataPath(id), os.O_RDONLY|noFollow, 0)
}

// Claim returns the oldest message due for delivery and marks it in flight.
// The lease is process-local: a single instance owns its spool directory.
func (s *Spool) Claim(now time.Time) (*Meta, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var due []*Meta
	for id, m := range s.index {
		if s.leased[id] || m.NextAttempt.After(now) {
			continue
		}
		due = append(due, m)
	}
	if len(due) == 0 {
		return nil, false
	}
	sort.Slice(due, func(i, j int) bool {
		return due[i].Envelope.Received.Before(due[j].Envelope.Received)
	})
	m := due[0]
	s.leased[m.ID] = true
	c := *m
	return &c, true
}

// Release returns a message to the queue with an updated retry state.
func (s *Spool) Release(m *Meta) error {
	if err := s.writeMeta(m); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *m
	s.index[m.ID] = &c
	delete(s.leased, m.ID)
	return nil
}

// Remove deletes a delivered message.
func (s *Spool) Remove(id ID) error {
	if !id.valid() {
		return ErrInvalidID
	}
	s.mu.Lock()
	delete(s.index, id)
	delete(s.leased, id)
	s.mu.Unlock()

	if err := os.Remove(s.metaPath(id)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := removeRetry(s.dataPath(id)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDir(s.queue)
}

// removeRetry unlinks a path, retrying briefly. On Windows an on-access
// scanner or a backup agent can hold a handle for a few milliseconds after
// the file was last written, which surfaces as a sharing violation rather
// than as a missing file. Retrying costs nothing on Unix, where the first
// attempt succeeds. A body left behind after the metadata was removed is not
// redelivered -- Open() discards bodies without metadata at startup -- so
// this only avoids the disk staying occupied until the next restart.
func removeRetry(path string) error {
	var err error
	for i := 0; i < 5; i++ {
		if err = os.Remove(path); err == nil || os.IsNotExist(err) {
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
	delete(s.index, m.ID)
	delete(s.leased, m.ID)
	s.mu.Unlock()

	var onDisk int64
	for _, ext := range []string{".json", ".eml"} {
		src := filepath.Join(s.queue, m.ID.String()+ext)
		dst := filepath.Join(s.failed, m.ID.String()+ext)
		if fi, err := os.Stat(src); err == nil {
			onDisk += fi.Size()
		}
		if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	// Still counted against the quota, from the other index. The message left
	// the queue; it did not leave the disk.
	s.mu.Lock()
	s.failedIndex[m.ID] = failedEntry{size: onDisk, at: time.Now()}
	s.mu.Unlock()

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
	s.mu.Lock()
	ttl := s.failedTTL
	if ttl <= 0 {
		s.mu.Unlock()
		return 0, 0
	}
	var expired []ID
	for id, e := range s.failedIndex {
		if now.Sub(e.at) > ttl {
			expired = append(expired, id)
		}
	}
	s.mu.Unlock()

	for _, id := range expired {
		for _, ext := range []string{".json", ".eml"} {
			if err := removeRetry(filepath.Join(s.failed, id.String()+ext)); err != nil && !os.IsNotExist(err) {
				// Leave it indexed so the next sweep tries again rather than
				// losing track of bytes that are still on the disk.
				continue
			}
		}
		s.mu.Lock()
		if e, still := s.failedIndex[id]; still {
			delete(s.failedIndex, id)
			removed++
			freed += e.size
		}
		s.mu.Unlock()
	}
	if removed > 0 {
		_ = syncDir(s.failed)
	}
	return removed, freed
}

// Len reports the number of queued messages, used by metrics and the
// shutdown path.
func (s *Spool) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}

// RouteDepth is the queue depth of one route, split by whether a message is
// claimable now or waiting for its next attempt.
type RouteDepth struct {
	Queued       int
	Deferred     int
	OldestQueued time.Time // zero if Queued == 0; oldest Received among claimable messages
}

// QueueDepth reports queue depth per route, read by the metrics endpoint and
// the API's queue view on every request. A message counts as Deferred when
// its next attempt lies in the future — a retry backoff or a rate limit
// hold — and as Queued otherwise, including one currently leased to a
// worker: it is neither waiting nor sitting idle, but it has not left the
// queue either.
func (s *Spool) QueueDepth(now time.Time) map[string]RouteDepth {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]RouteDepth{}
	for id, m := range s.index {
		d := out[m.Envelope.Route]
		if !s.leased[id] && m.NextAttempt.After(now) {
			d.Deferred++
		} else {
			d.Queued++
			if d.OldestQueued.IsZero() || m.Envelope.Received.Before(d.OldestQueued) {
				d.OldestQueued = m.Envelope.Received
			}
		}
		out[m.Envelope.Route] = d
	}
	return out
}

// ErrBusy is returned by Requeue and Discard for a message currently leased
// to a delivery worker. Acting on it anyway would race the worker's own
// Release or Remove call, which could resurrect a message Discard just
// deleted; the caller is expected to retry shortly.
var ErrBusy = errors.New("spool: message is currently being delivered")

// Requeue moves a message back into the live queue for immediate retry,
// resetting its attempt counter so its retry backoff starts over. It works
// whether the message is currently active (queued or deferred) or was moved
// aside to spool/failed after a permanent failure or expiry.
func (s *Spool) Requeue(id ID) error {
	if !id.valid() {
		return ErrInvalidID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.leased[id] {
		return ErrBusy
	}

	if m, ok := s.index[id]; ok {
		reset := *m
		reset.Attempts, reset.NextAttempt, reset.LastError = 0, time.Now(), ""
		if err := s.writeMeta(&reset); err != nil {
			return err
		}
		s.index[id] = &reset
		return nil
	}

	failedMeta := filepath.Join(s.failed, id.String()+".json")
	//#nosec G304 -- failedMeta is s.failed joined with an ID the caller has already put through ParseID
	b, err := os.ReadFile(failedMeta)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	if m.ID != id {
		return fmt.Errorf("spool: metadata for %s claims id %s", id, m.ID)
	}
	m.Attempts, m.NextAttempt, m.LastError = 0, time.Now(), ""

	if err := os.Rename(filepath.Join(s.failed, id.String()+".eml"), s.dataPath(id)); err != nil {
		return err
	}
	if err := s.writeMeta(&m); err != nil {
		_ = removeRetry(s.dataPath(id))
		return err
	}
	if err := os.Remove(failedMeta); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := syncDir(s.queue); err != nil {
		return err
	}
	if err := syncDir(s.failed); err != nil {
		return err
	}
	s.index[id] = &m
	delete(s.failedIndex, id)
	return nil
}

// Discard permanently removes a message's spool files, wherever it
// currently sits (queued, deferred or failed), without touching its history
// in the store: the admin "delete" action retains history by design, and
// only the store's own retention job ever purges a history row.
func (s *Spool) Discard(id ID) error {
	if !id.valid() {
		return ErrInvalidID
	}
	s.mu.Lock()
	if s.leased[id] {
		s.mu.Unlock()
		return ErrBusy
	}
	delete(s.index, id)
	delete(s.failedIndex, id)
	s.mu.Unlock()

	removed := false
	for _, dir := range []string{s.queue, s.failed} {
		for _, ext := range []string{".json", ".eml"} {
			if err := os.Remove(filepath.Join(dir, id.String()+ext)); err == nil {
				removed = true
			} else if !os.IsNotExist(err) {
				return err
			}
		}
	}
	if !removed {
		return ErrNotFound
	}
	if err := syncDir(s.queue); err != nil {
		return err
	}
	return syncDir(s.failed)
}

// spoolSize returns the total size in bytes the spool occupies: queued
// messages plus the permanently failed ones kept in spool/failed. Failed
// messages are counted because they are still on the filesystem the quota
// exists to protect -- summing only the live index let a client that produced
// nothing but permanent failures fill the disk without the quota ever seeing
// it.
func (s *Spool) spoolSize() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var total int64
	for _, m := range s.index {
		total += m.Envelope.Size
	}
	for _, e := range s.failedIndex {
		total += e.size
	}
	return total
}

// SetQuota configures the maximum spool size and warning threshold. A maxGB of
// zero or less means no quota; the caller is expected to have rejected a
// negative value at configuration load time, and the multiplication is done in
// int64 so that a large value cannot wrap into one.
func (s *Spool) SetQuota(maxGB int, warnPercent int) {
	const gib = 1024 * 1024 * 1024
	s.mu.Lock()
	defer s.mu.Unlock()
	s.warnQuotaPercent = warnPercent
	switch {
	case maxGB <= 0:
		s.maxQuotaBytes = 0
	case maxGB > math.MaxInt64/gib:
		// config.Validate rejects a value this large. Clamping rather than
		// letting the multiplication wrap means one that reached here anyway
		// still enforces something, instead of turning into no quota at all.
		s.maxQuotaBytes = math.MaxInt64
	default:
		s.maxQuotaBytes = int64(maxGB) * gib
	}
}

// SetFailedRetention configures how long spool/failed keeps a permanently
// failed message's files. Zero disables the sweep.
func (s *Spool) SetFailedRetention(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failedTTL = d
}

// syncDir and ensureMode are platform-specific; see dirsync_unix.go and
// dirsync_windows.go.
