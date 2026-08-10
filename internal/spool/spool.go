// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package spool provides the durable on-disk message queue.
package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	mu               sync.Mutex
	index            map[ID]*Meta
	leased           map[ID]bool
	maxQuotaBytes    int64
	warnQuotaPercent int
}

// Open prepares the spool directories and recovers any prior state.
func Open(dataDir string) (*Spool, error) {
	s := &Spool{
		root:   dataDir,
		tmp:    filepath.Join(dataDir, "spool", "tmp"),
		queue:  filepath.Join(dataDir, "spool", "queue"),
		failed: filepath.Join(dataDir, "spool", "failed"),
		index:  map[ID]*Meta{},
		leased: map[ID]bool{},
	}
	for _, d := range []string{s.tmp, s.queue, s.failed} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil {
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
	if err := os.Remove(s.dataPath(id)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDir(s.queue)
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

	for _, ext := range []string{".json", ".eml"} {
		src := filepath.Join(s.queue, m.ID.String()+ext)
		dst := filepath.Join(s.failed, m.ID.String()+ext)
		if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return syncDir(s.failed)
}

// Len reports the number of queued messages, used by metrics and the
// shutdown path.
func (s *Spool) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}

// spoolSize returns the total size in bytes of all queued messages.
func (s *Spool) spoolSize() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var total int64
	for _, m := range s.index {
		total += m.Envelope.Size
	}
	return total
}

// SetQuota configures the maximum spool size and warning threshold.
func (s *Spool) SetQuota(maxGB int, warnPercent int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxQuotaBytes = int64(maxGB) * 1024 * 1024 * 1024
	s.warnQuotaPercent = warnPercent
}

// syncDir flushes a directory entry so that a rename survives a power loss.
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	// Directory fsync is not supported on Windows and fails with EACCES or
	// similar there; that is not an error worth aborting a delivery for.
	// On other platforms, fsync errors should be reported.
	if err := d.Sync(); err != nil {
		if errors.Is(err, os.ErrInvalid) {
			return nil
		}
		return err
	}
	return nil
}
