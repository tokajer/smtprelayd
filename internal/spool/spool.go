// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package spool provides the durable on-disk message queue.
//
// A message moves through these states, each a method on Spool:
//
//	Stage ──Commit──▶ queued ──Claim──▶ leased ──Remove──▶ (gone: delivered)
//	                    ▲                 │
//	                    │                 ├──Defer────▶ queued, later, index only
//	                    │                 ├──Release──▶ queued, later, metadata written
//	                    │                 └──Fail─────▶ failed (spool/failed)
//	                    │                                 │
//	                    └────────Requeue──────────────────┘
//	                                                      └──SweepFailed / Discard──▶ (gone)
//
// Discard also removes a queued or deferred message. A leased message refuses
// Requeue and Discard with ErrBusy: the worker holding it is the only thing
// that may decide its fate.
package spool

import (
	"container/heap"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Envelope is everything known about a message at the moment it was accepted.
type Envelope struct {
	From string   `json:"from"`
	To   []string `json:"to"`

	// Origin is who composed the message, and it is the grouping key the
	// relay's own reporting uses: a client's name for relayed mail, a
	// canary's name for a probe, a notification source for a digest or an
	// expiry warning. internal/bounce groups digest entries by it, which is
	// what keeps each canary's failures reported separately, and
	// config.reservedNames refuses a client name that would collide with a
	// source the relay uses itself.
	//
	// It was called Client until 2026-09-21, which named one of the three
	// things it holds and needed saying again at every place that set or read
	// it. The JSON tag keeps the old spelling: this is persisted metadata, and
	// a binary rolled back has to go on reading a queued message's origin.
	Origin string `json:"client"`

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

	// Kind says who composed the message. It is the value the delivery
	// manager switches on; the two booleans below are the same fact in the
	// representation earlier versions wrote.
	Kind Kind `json:"kind,omitempty"`

	// Notification and Canary are the pre-2026-09-21 on-disk representation
	// of Kind, kept for compatibility in both directions. normalizeKind
	// fills Kind from them when metadata written by an earlier version is
	// read, and fills them from Kind before metadata is written, so a binary
	// rolled back to a version that knows only these two still reads a
	// notification as a notification -- which matters, because that version
	// would otherwise let a notification's own failure enqueue another one.
	//
	// Nothing outside normalizeKind may read them: two spellings of one fact
	// is exactly the shape that lets a message be both and neither.
	Notification bool `json:"notification,omitempty"`
	Canary       bool `json:"canary,omitempty"`
}

// Kind classifies who composed a message. It decides how a delivery outcome
// is counted and whether a permanent failure is something to notify about.
//
// A string rather than an iota: it is persisted, so its values have to mean
// the same thing across versions without depending on declaration order, and
// the empty value has to be the one a message written before the field
// existed decodes to. Adding a fourth kind is now one constant and one
// branch, rather than a fourth boolean and a fourth combination of booleans
// that cannot be expressed as an error.
type Kind string

const (
	KindClient       Kind = ""             // accepted from a client through a listener
	KindNotification Kind = "notification" // composed by the bounce notifier or the expiry watcher
	KindCanary       Kind = "canary"       // composed by a canary runner
)

// normalizeKind settles Kind and the two legacy booleans against each other,
// whichever of them arrived populated. It is called on every envelope read
// from disk and on every envelope about to be written, so the two
// representations can never disagree in a file or in memory.
func (e *Envelope) normalizeKind() {
	switch {
	case e.Kind != "":
	case e.Notification:
		e.Kind = KindNotification
	case e.Canary:
		e.Kind = KindCanary
	}
	e.Notification = e.Kind == KindNotification
	e.Canary = e.Kind == KindCanary
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
	root  string
	tmp   string
	queue string

	// Three locks, not one. They guard three sets of state that share no
	// invariant: the live queue below, the mirror of spool/failed, and the
	// quota ledger. One mutex over all of them meant a retention sweep of
	// spool/failed, or a dashboard asking for the quota, stopped Commit and
	// ClaimBatch -- and it is why QueueDepth needed a cache and Requeue
	// needed to hold a lease instead of the lock.
	//
	// The other two are values of their own rather than more fields here,
	// since 2026-09-21. That is what makes "never held nested" a property of
	// the call graph instead of a comment: neither type can reach the live
	// queue, so the only place the three meet is Spool.liveAndFailedBytes,
	// which asks each in turn and has released one lock before taking the
	// next.

	// mu guards the live queue: index, leased, indexBytes and the depth
	// cache derived from them.
	mu     sync.Mutex
	index  map[ID]*Meta
	leased map[ID]bool

	// indexBytes is the sum of Envelope.Size over index, maintained by
	// putLocked and dropLocked. Kept as a running total because the quota
	// check runs on every accepted message, and summing the map there cost
	// one walk of the whole queue per commit.
	indexBytes int64

	// depthCache holds the last QueueDepth result, with the moment it
	// describes and how long it may be reused for. Guarded by mu.
	depthCache  map[string]RouteDepth
	depthAt     time.Time
	depthWindow time.Duration

	// failed mirrors the spool/failed directory and owns its path; quota is
	// the size ceiling and what has been admitted against it. See failed.go
	// and quota.go.
	failed *failedStore
	quota  *quotaLedger
}

// putLocked inserts or replaces a message in the live index, keeping
// indexBytes in step. Callers hold s.mu.
func (s *Spool) putLocked(m *Meta) {
	if old, ok := s.index[m.ID]; ok {
		s.indexBytes -= old.Envelope.Size
	}
	s.index[m.ID] = m
	s.indexBytes += m.Envelope.Size
}

// dropLocked removes a message from the live index, keeping indexBytes in
// step. Callers hold s.mu.
func (s *Spool) dropLocked(id ID) {
	if old, ok := s.index[id]; ok {
		s.indexBytes -= old.Envelope.Size
		delete(s.index, id)
	}
}

// Open prepares the spool directories and recovers any prior state.
func Open(dataDir string) (*Spool, error) {
	s := &Spool{
		root:   dataDir,
		tmp:    filepath.Join(dataDir, "spool", "tmp"),
		queue:  filepath.Join(dataDir, "spool", "queue"),
		index:  map[ID]*Meta{},
		leased: map[ID]bool{},
		failed: newFailedStore(filepath.Join(dataDir, "spool", "failed")),
		quota:  newQuotaLedger(),
	}
	for _, d := range []string{s.tmp, s.queue, s.failed.dir} {
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

	metas, bodies, err := s.scanQueue()
	if err != nil {
		return err
	}

	indexed := make(map[ID]bool, len(metas))
	for _, id := range metas {
		if !bodies[id] {
			// Metadata without a body cannot be delivered and cannot be
			// bounced meaningfully; drop it rather than retry forever.
			//
			// Answered from the listing rather than with os.Stat per
			// message: the directory pass already knows which bodies are
			// there, and at 200 000 queued messages that stat cost 0.89s of
			// a startup the Windows SCM gives 30 seconds for.
			_ = os.Remove(s.metaPath(id))
			continue
		}
		m, err := s.readMeta(id)
		if err != nil {
			continue
		}
		// No lock: Open has not returned, so nothing else can reach this
		// spool yet. putLocked is still used so indexBytes cannot be
		// forgotten here the way a bare map write would let it be.
		s.putLocked(m)
		indexed[id] = true
	}

	// A body without metadata is an interrupted enqueue: the sender was never
	// told the message was accepted, so removing it loses nothing. Metadata
	// that would not parse leaves its body here too, for the same reason --
	// nothing can be delivered from it.
	for id := range bodies {
		if !indexed[id] {
			_ = os.Remove(s.dataPath(id))
		}
	}

	return s.failed.reindex()
}

// syncDirFn is syncDir, indirected so that a test can make it fail. The only
// thing that reads it is Commit, whose behaviour when the directory sync
// fails -- unlinking a pair that is already renamed into place, so recover()
// cannot re-index a message the client was told was not accepted -- is
// otherwise unreachable without a filesystem that refuses fsync on demand.
var syncDirFn = syncDir

// recoverBatch is how many directory entries one ReadDir call returns.
const recoverBatch = 4096

// scanQueue lists the queue directory once, returning the ids that have
// metadata and the set that have a body.
//
// os.ReadDir is not used here: it sorts the whole listing by filename and
// materialises it, and recover needs neither. At 200 000 queued messages
// (400 000 files) the sorted whole-directory read measured 191ms against
// 126ms for batches, and the slice it builds is one entry per file.
func (s *Spool) scanQueue() (metas []ID, bodies map[ID]bool, err error) {
	d, err := os.Open(s.queue)
	if err != nil {
		return nil, nil, err
	}
	defer d.Close()

	bodies = map[ID]bool{}
	for {
		batch, err := d.ReadDir(recoverBatch)
		for _, e := range batch {
			name := e.Name()
			switch {
			case strings.HasSuffix(name, ".json"):
				if id, err := ParseID(strings.TrimSuffix(name, ".json")); err == nil {
					metas = append(metas, id)
				}
			case strings.HasSuffix(name, ".eml"):
				if id, err := ParseID(strings.TrimSuffix(name, ".eml")); err == nil {
					bodies[id] = true
				} else {
					// A body whose name is not a queue id can never be
					// matched to metadata, so it would sit here forever.
					_ = os.Remove(filepath.Join(s.queue, name))
				}
			}
		}
		if errors.Is(err, io.EOF) || len(batch) == 0 {
			break
		}
		if err != nil {
			return nil, nil, err
		}
	}
	return metas, bodies, nil
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

	// Reserved, not merely checked: two commits racing past one check could
	// each fit alone and overshoot together, by up to the concurrency times
	// the largest message. The reservation is released once the copy is in
	// the index, where its size counts by itself.
	if err := s.reserveQuota(st.size); err != nil {
		return "", err
	}
	defer s.releaseQuota(st.size)

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
	env.normalizeKind()
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
	if err := syncDirFn(s.queue); err != nil {
		// Both files are in place, and the caller is about to be told the
		// commit failed -- so they must not stay. recover() re-indexes a
		// metadata/body pair at the next start, while the listener has
		// already withdrawn the sibling copies and answered 4xx, so the
		// client has retried: leaving them here delivers the message twice.
		// Body first and both attempted, the order Remove gives its reasons
		// for.
		_ = removeRetry(s.dataPath(id))
		_ = removeRetry(s.metaPath(id))
		return "", err
	}

	s.mu.Lock()
	s.putLocked(m)
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
	// So that a version reading only the legacy booleans still sees the
	// kind; see the note on Envelope.Notification.
	m.Envelope.normalizeKind()
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
	m.Envelope.normalizeKind()
	return &m, nil
}

// OpenBody returns the message body for reading. Named apart from the
// package-level Open, which prepares a spool directory: the two used to share
// a name and mean different things.
func (s *Spool) OpenBody(id ID) (*os.File, error) {
	if !id.valid() {
		return nil, ErrInvalidID
	}
	return os.OpenFile(s.dataPath(id), os.O_RDONLY|noFollow, 0)
}

// Claim returns the oldest message due for delivery and marks it in flight.
// It is ClaimBatch for one message; the dispatcher uses ClaimBatch, this is
// for callers that want exactly one.
func (s *Spool) Claim(now time.Time) (*Meta, bool) {
	batch := s.ClaimBatch(now, 1, nil)
	if len(batch) == 0 {
		return nil, false
	}
	return batch[0], true
}

// ClaimBatch returns up to max due messages, oldest first by Received, and
// marks every one of them in flight. The lease is process-local: a single
// instance owns its spool directory. skip, if non-nil, excludes the routes
// it reports true for; the dispatcher passes the routes it has already
// found saturated in this tick.
//
// One scan for many messages, not one per message. The dispatcher used to
// call Claim once per due message, and Claim scans the whole index, so a
// tick over n due messages cost n scans -- quadratic, and worst exactly when
// a smarthost hangs and every message is held and re-found on the next
// tick. Measured on the one-at-a-time drain before this existed: 22 hours
// for a million messages. A bounded max-heap keeps the max oldest seen so
// far in O(n log max) per scan, and skip lets a tick end after one scan per
// saturated route instead of one per message on it.
func (s *Spool) ClaimBatch(now time.Time, max int, skip func(route string) bool) []*Meta {
	if max <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	h := make(newestFirst, 0, max)
	for id, m := range s.index {
		if s.leased[id] || m.NextAttempt.After(now) {
			continue
		}
		if skip != nil && skip(m.Envelope.Route) {
			continue
		}
		switch {
		case len(h) < max:
			heap.Push(&h, m)
		case m.Envelope.Received.Before(h[0].Envelope.Received):
			h[0] = m
			heap.Fix(&h, 0)
		}
	}
	out := make([]*Meta, len(h))
	for i := len(out) - 1; i >= 0; i-- {
		m := heap.Pop(&h).(*Meta)
		s.leased[m.ID] = true
		c := *m
		out[i] = &c
	}
	return out
}

// newestFirst is a max-heap by Received: its root is the newest of the
// messages kept, which is the one to evict when an older one turns up.
type newestFirst []*Meta

func (h newestFirst) Len() int { return len(h) }
func (h newestFirst) Less(i, j int) bool {
	return h[i].Envelope.Received.After(h[j].Envelope.Received)
}
func (h newestFirst) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *newestFirst) Push(x any)   { *h = append(*h, x.(*Meta)) }
func (h *newestFirst) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// Defer puts a leased message back with a later attempt time without writing
// its metadata. It is for scheduling decisions that only matter while the
// process runs -- no worker slot free, route paced -- where the message was
// never offered to the smarthost and nothing about it has actually changed.
// A restart makes it due again, which is exactly right: the reason it was
// deferred did not survive either.
//
// Release is the one to use whenever the deferral records something that has
// to outlive the process, such as an attempt that failed and its backoff.
func (s *Spool) Defer(m *Meta, until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.index[m.ID]; ok {
		cur.NextAttempt = until
	}
	delete(s.leased, m.ID)
}

// Release returns a message to the queue with an updated retry state.
func (s *Spool) Release(m *Meta) error {
	if err := s.writeMeta(m); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *m
	s.putLocked(&c)
	delete(s.leased, m.ID)
	return nil
}

// Remove deletes a delivered message.
func (s *Spool) Remove(id ID) error {
	if !id.valid() {
		return ErrInvalidID
	}
	s.mu.Lock()
	s.dropLocked(id)
	delete(s.leased, id)
	s.mu.Unlock()

	// Body first, metadata second, and both through removeRetry. The order is
	// what makes a partial failure safe rather than catastrophic: recover()
	// drops metadata whose body is gone, so a leftover .json is inert, while a
	// leftover .json *and* .eml is re-indexed at the next start and the
	// message goes out a second time. The metadata is unlinked even when the
	// body could not be, for that same reason -- a stranded body costs disk
	// until the next start, a stranded pair costs a duplicate delivery.
	dataErr := removeRetry(s.dataPath(id))
	metaErr := removeRetry(s.metaPath(id))
	if err := firstRealError(dataErr, metaErr); err != nil {
		return err
	}
	return syncDir(s.queue)
}

// firstRealError returns the first error that is not simply a missing file.
// Remove and Discard are both reached for messages whose files may already be
// half gone, which is not a failure of the removal.
func firstRealError(errs ...error) error {
	for _, err := range errs {
		if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// removeRetry unlinks a path, retrying briefly. On Windows an on-access
// scanner or a backup agent can hold a handle for a few milliseconds after
// the file was last written, which surfaces as a sharing violation rather
// than as a missing file. Retrying costs nothing on Unix, where the first
// attempt succeeds.
//
// It matters most on the metadata file. A body left behind is inert, because
// recover() discards bodies without metadata at startup, so losing that race
// only occupies disk until the next restart -- but metadata left behind
// beside its body is re-indexed at the next start and delivered again. The
// callers unlink the body first for that reason.
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

// Len reports the number of queued messages, used by metrics and the
// shutdown path.
func (s *Spool) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}

// Has reports whether a message still has spool files, either live or
// permanently failed. The queue view is built from the history store, which
// can list a message the spool no longer holds; this is what lets the view
// say so instead of offering a requeue that can only fail.
func (s *Spool) Has(id ID) bool {
	if !id.valid() {
		return false
	}
	s.mu.Lock()
	_, live := s.index[id]
	s.mu.Unlock()
	if live {
		return true
	}
	return s.failed.has(id)
}

// RouteDepth is the queue depth of one route, split by whether a message is
// claimable now or waiting for its next attempt.
type RouteDepth struct {
	Queued       int
	Deferred     int
	OldestQueued time.Time // zero if Queued == 0; oldest Received among claimable messages
}

const (
	// depthCacheFloor is the shortest a computed depth is reused for.
	depthCacheFloor = time.Second

	// depthScanBudget holds a computed depth for this many times the scan's
	// own duration, so walking the index never costs more than 1/budget of
	// wall time however deep the queue gets. At a million queued messages the
	// scan measured about 200ms, which this turns into one scan per four
	// seconds instead of one per reader.
	depthScanBudget = 20
)

// QueueDepth reports queue depth per route. A message counts as Deferred when
// its next attempt lies in the future — a retry backoff or a rate limit
// hold — and as Queued otherwise, including one currently leased to a
// worker: it is neither waiting nor sitting idle, but it has not left the
// queue either.
//
// The result may lag by up to the cache window described above. That is
// deliberate, and it is what the caching is for: the dashboard's sidebar, the
// API's health and routes endpoints and the metrics exposition all call this,
// so the number of index scans was set by how many people were watching. Each
// scan holds the mutex that Commit, ClaimBatch, Remove and Defer also take,
// so it stops mail intake and dispatch outright -- measured at 179ms for a
// million queued messages, per dashboard page view. Every consumer of this is
// a gauge nobody acts on within a second, so the trade is a depth that can be
// a few seconds old against a mail path that no longer pauses when somebody
// opens a page.
//
// The split cannot be maintained incrementally the way a plain count could:
// a message moves from Deferred to Queued when its NextAttempt passes, with
// no code running at all, so there is no mutation to hook. That is why this
// is a cache and not a set of counters.
func (s *Spool) QueueDepth(now time.Time) map[string]RouteDepth {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Only a now that has moved forward by less than the window may reuse the
	// cache: the split is a function of now, so a caller asking about a
	// different moment -- a test reaching a day ahead, or a clock stepped
	// backwards -- has to be answered from the index.
	if s.depthCache != nil {
		if age := now.Sub(s.depthAt); age >= 0 && age < s.depthWindow {
			return cloneDepth(s.depthCache)
		}
	}

	started := time.Now()
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

	window := time.Duration(depthScanBudget) * time.Since(started)
	if window < depthCacheFloor {
		window = depthCacheFloor
	}
	s.depthCache, s.depthAt, s.depthWindow = out, now, window
	return cloneDepth(out)
}

// cloneDepth copies the cached map out, so a caller cannot write into the
// cache it was served from.
func cloneDepth(in map[string]RouteDepth) map[string]RouteDepth {
	out := make(map[string]RouteDepth, len(in))
	for k, v := range in {
		out[k] = v
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
//
// The message is leased for the duration rather than the mutex being held
// across the file operations. Until 2026-09-18 s.mu covered writeMeta's
// fsync and, for a failed message, a rename and two directory syncs -- and
// the quota check on every listener commit, ClaimBatch and QueueDepth all
// waited behind each one, so a bulk requeue of a thousand messages stalled
// the whole relay for a thousand fsyncs. The lease gives the same guarantee
// the lock did: ClaimBatch skips a leased message, and Discard or a second
// Requeue answer ErrBusy instead of racing the renames below.
func (s *Spool) Requeue(id ID) error {
	if !id.valid() {
		return ErrInvalidID
	}
	s.mu.Lock()
	if s.leased[id] {
		s.mu.Unlock()
		return ErrBusy
	}
	s.leased[id] = true
	cur, live := s.index[id]
	var reset Meta
	if live {
		reset = *cur
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.leased, id)
		s.mu.Unlock()
	}()

	if live {
		return s.requeueLive(&reset)
	}
	return s.requeueFailed(id)
}

// requeueLive resets a queued or deferred message in place. The caller holds
// the lease; m is its private copy of the metadata.
func (s *Spool) requeueLive(m *Meta) error {
	m.Attempts, m.NextAttempt, m.LastError = 0, time.Now(), ""
	if err := s.writeMeta(m); err != nil {
		return err
	}
	s.mu.Lock()
	s.putLocked(m)
	s.mu.Unlock()
	return nil
}

// requeueFailed moves a message from spool/failed back into the queue. The
// caller holds the lease, which is what keeps Discard away from the renames.
func (s *Spool) requeueFailed(id ID) error {
	failedMeta := s.failed.path(id, ".json")
	//#nosec G304 -- failedMeta is spool/failed joined with an ID the caller has already put through ParseID
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
	m.Envelope.normalizeKind()
	m.Attempts, m.NextAttempt, m.LastError = 0, time.Now(), ""

	// Through renameRetry for the reason Fail uses it: on Windows a handle
	// held by a scanner makes this fail with a sharing violation rather than
	// with a missing file, and losing that race here refuses an operator's
	// requeue for a message that is perfectly intact.
	failedBody := s.failed.path(id, ".eml")
	if err := renameRetry(failedBody, s.dataPath(id)); err != nil {
		return err
	}
	if err := s.writeMeta(&m); err != nil {
		// The body goes back where it came from rather than being unlinked.
		// Its metadata is still in spool/failed, so unlinking here destroyed
		// the only copy of the message while leaving the dashboard listing it
		// as requeueable and the quota charging for it -- the one path in this
		// package that could lose a body outright. Remove's "a stranded body
		// is inert" reasoning does not apply: that is about the queue
		// directory, which recover() sweeps, and the surviving metadata here
		// is in spool/failed, which nothing sweeps.
		//
		// If the rollback itself fails the body is left in the queue
		// directory, where recover() drops a body without metadata at the
		// next start. Both errors are reported: the second one is why the
		// message is now only in the journal.
		if rerr := renameRetry(s.dataPath(id), failedBody); rerr != nil {
			return errors.Join(err, rerr)
		}
		return err
	}
	if err := os.Remove(failedMeta); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := syncDir(s.queue); err != nil {
		return err
	}
	if err := syncDir(s.failed.dir); err != nil {
		return err
	}
	s.mu.Lock()
	s.putLocked(&m)
	s.mu.Unlock()
	s.failed.drop(id)
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
	// Leased for the duration, the way Requeue takes one, rather than dropped
	// from the index up front. The lease is what keeps ClaimBatch and a
	// concurrent Requeue or Discard away while the files go, so the unlinks
	// can happen before the accounting changes -- and that order is the whole
	// point: dropping both index entries first and then failing to unlink left
	// the files on disk charged to nobody, invisible to the quota and to
	// QueueDepth until a restart re-read the directories. It is the invariant
	// Fail and SweepFailed already hold, and this was the last place that did
	// not.
	s.mu.Lock()
	if s.leased[id] {
		s.mu.Unlock()
		return ErrBusy
	}
	s.leased[id] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.leased, id)
		s.mu.Unlock()
	}()

	removed := false
	// Body before metadata, through removeRetry, for the reason Remove gives:
	// a stranded pair in the queue directory is re-indexed at the next start,
	// so a message the operator deleted would be delivered after a restart.
	// Both files are attempted before any error is reported, so one that
	// cannot be unlinked does not leave the other in place.
	var failure error
	for _, dir := range []string{s.queue, s.failed.dir} {
		for _, ext := range []string{".eml", ".json"} {
			err := removeRetry(filepath.Join(dir, id.String()+ext))
			switch {
			case err == nil:
				removed = true
			case !os.IsNotExist(err) && failure == nil:
				failure = err
			}
		}
	}
	if failure != nil {
		// Whatever could not be unlinked is still occupying the filesystem the
		// quota exists to protect, so it stays accounted for: both index
		// entries are left exactly as they were, and the next Discard or the
		// next restart tries again against state that still describes the
		// disk.
		return failure
	}

	// The files are gone, so the accounting follows. Dropping the live entry
	// even when nothing was removed is deliberate: that is a message history
	// still calls queued while its spool files have already vanished, and the
	// index was the thing that was wrong.
	s.mu.Lock()
	s.dropLocked(id)
	s.mu.Unlock()
	s.failed.drop(id)

	if !removed {
		return ErrNotFound
	}
	if err := syncDir(s.queue); err != nil {
		return err
	}
	return syncDir(s.failed.dir)
}

// syncDir and ensureMode are platform-specific; see dirsync_unix.go and
// dirsync_windows.go.
