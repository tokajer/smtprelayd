// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package spool

import (
	"math"
	"sync"
)

// Quota accounting: what the spool occupies and the ceiling it is held to.

// quotaLedger is the ceiling and what has been admitted against it. It holds
// no idea of what the spool currently occupies -- Spool composes that from the
// live index and the failed store and passes it in, which is what keeps this
// lock from ever being held while one of those is taken.
//
// A type of its own for the reason failedStore is one: it was three fields on
// Spool behind a quotaMu, so every method could reach it and the lock
// ordering was a comment.
type quotaLedger struct {
	mu          sync.Mutex
	maxBytes    int64
	warnPercent int

	// reserved is what commits in flight have been admitted for and not yet
	// indexed; see reserve.
	reserved int64
}

func newQuotaLedger() *quotaLedger { return &quotaLedger{} }

// limits reports the configured ceiling and warning threshold.
func (q *quotaLedger) limits() (maxBytes int64, warnPercent int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.maxBytes, q.warnPercent
}

// reservedBytes is what is admitted but not yet indexed.
func (q *quotaLedger) reservedBytes() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.reserved
}

// reserve admits n more bytes against the ceiling and holds them until
// release, so that concurrent commits are judged against each other rather
// than each against the size before any of them: two commits racing past one
// check could each fit alone and overshoot together, by up to the concurrency
// times the largest message.
//
// occupied is what the spool already holds, read by the caller before this
// lock is taken, so two callers can share one view of it -- but the
// reservation itself is made here against the current reserved total, which
// is what makes the second caller see the first one's claim.
func (q *quotaLedger) reserve(n, occupied int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.maxBytes > 0 && occupied+q.reserved+n > q.maxBytes {
		return ErrQuotaExceeded
	}
	q.reserved += n
	return nil
}

func (q *quotaLedger) release(n int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reserved -= n
}

// set configures the maximum spool size and warning threshold. A maxGB of
// zero or less means no quota; the caller is expected to have rejected a
// negative value at configuration load time, and the multiplication is done in
// int64 so that a large value cannot wrap into one.
func (q *quotaLedger) set(maxGB, warnPercent int) {
	const gib = 1024 * 1024 * 1024
	q.mu.Lock()
	defer q.mu.Unlock()
	q.warnPercent = warnPercent
	switch {
	case maxGB <= 0:
		q.maxBytes = 0
	case maxGB > math.MaxInt64/gib:
		// config.Validate rejects a value this large. Clamping rather than
		// letting the multiplication wrap means one that reached here anyway
		// still enforces something, instead of turning into no quota at all.
		q.maxBytes = math.MaxInt64
	default:
		q.maxBytes = int64(maxGB) * gib
	}
}

// usedBytes is what the spool occupies: queued messages, the permanently
// failed ones kept in spool/failed, and what commits in flight have been
// admitted for. Failed messages count because they are still on the
// filesystem the quota exists to protect -- summing only the live index let a
// client that produced nothing but permanent failures fill the disk without
// the quota ever seeing it.
//
// All three totals mean message bodies: the live index sums Envelope.Size and
// the failed store the body's own size on disk, which differ only by the
// per-copy Received header Commit prepends. The metadata file is in neither,
// so the total understates the directories by one small JSON file per
// message -- uniform, a few hundred bytes, and against a ceiling in
// gigabytes.
//
// The three totals are read under their own locks, one after another, never
// nested -- which this composition is what guarantees: each source hands back
// a number and has released its lock by the time the next is asked. A message
// moving from the live index to spool/failed between two of those reads is
// therefore counted twice or not at all, for as long as the next lock
// acquisition takes; requeueFailed admits the same skew in the other
// direction, entering the live index before it leaves the failed store. That
// is deliberate: the alternative is one lock over the queue, the failed mirror
// and the ledger, which is what made a retention sweep stop mail intake. The
// error it admits is one message's size against a ceiling measured in
// gigabytes, and it cannot accumulate -- every call recomputes from the three
// running totals.
func (s *Spool) usedBytes() int64 {
	return s.liveAndFailedBytes() + s.quota.reservedBytes()
}

// liveAndFailedBytes is what is actually on disk, without the reservations.
// It is what reserve is judged against: a commit must not be admitted against
// a total that already includes its own reservation.
func (s *Spool) liveAndFailedBytes() int64 {
	s.mu.Lock()
	live := s.indexBytes
	s.mu.Unlock()

	return live + s.failed.occupied()
}

// spoolSize returns the total size in bytes the spool occupies. See usedBytes
// for what counts and why; this is the name the tests use.
func (s *Spool) spoolSize() int64 { return s.usedBytes() }

// reserveQuota admits n bytes for a commit in flight.
func (s *Spool) reserveQuota(n int64) error {
	return s.quota.reserve(n, s.liveAndFailedBytes())
}

func (s *Spool) releaseQuota(n int64) { s.quota.release(n) }

// QuotaWarning reports whether the spool has reached limits.spool_warn_percent
// of its configured quota. over is false whenever no quota or no warning
// threshold is configured. It does no logging itself and mutates nothing:
// this package holds no logger, so the caller (the delivery manager) is
// responsible for reporting the transition.
func (s *Spool) QuotaWarning() (used, quota int64, over bool) {
	quota, warnPercent := s.quota.limits()
	if quota <= 0 || warnPercent <= 0 {
		// Deliberately before usedBytes: with no threshold to cross there is
		// nothing to report, and walking the three totals for it would be
		// work whose result is discarded.
		return 0, quota, false
	}
	used = s.usedBytes()
	// quota may be math.MaxInt64 (quotaLedger.set clamps an oversized config
	// value to it), so quota*warnPercent could overflow. Dividing quota first
	// instead cannot overflow and loses at most 99 bytes of precision,
	// irrelevant for a threshold measured in gigabytes.
	over = used >= quota/100*int64(warnPercent)
	return used, quota, over
}

// SetQuota configures the maximum spool size and warning threshold; see
// quotaLedger.set.
func (s *Spool) SetQuota(maxGB int, warnPercent int) { s.quota.set(maxGB, warnPercent) }
