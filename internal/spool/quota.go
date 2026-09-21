// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package spool

import (
	"math"
)

// Quota accounting: what the spool occupies and the ceiling it is held to.
// The failed index counts too; see failed.go.

// usedBytes is what the spool occupies: queued messages, the permanently
// failed ones kept in spool/failed, and what commits in flight have been
// admitted for. Failed messages count because they are still on the
// filesystem the quota exists to protect -- summing only the live index let a
// client that produced nothing but permanent failures fill the disk without
// the quota ever seeing it.
//
// The three totals are read under their own locks, one after another, never
// nested. A message moving from the live index to spool/failed between two of
// those reads is therefore counted twice or not at all, for as long as the
// next lock acquisition takes. That is deliberate: the alternative is one
// lock over the queue, the failed mirror and the ledger, which is what made a
// retention sweep stop mail intake. The error it admits is one message's size
// against a ceiling measured in gigabytes, and it cannot accumulate -- every
// call recomputes from the three running totals.
func (s *Spool) usedBytes() int64 {
	s.mu.Lock()
	live := s.indexBytes
	s.mu.Unlock()

	s.failedMu.Lock()
	failed := s.failedBytes
	s.failedMu.Unlock()

	s.quotaMu.Lock()
	reserved := s.reserved
	s.quotaMu.Unlock()

	return live + failed + reserved
}

// spoolSize returns the total size in bytes the spool occupies. See usedBytes
// for what counts and why; this is the name the tests use.
func (s *Spool) spoolSize() int64 { return s.usedBytes() }

// reserveQuota admits n more bytes against the quota and holds them until
// releaseQuota, so that concurrent commits are judged against each other
// rather than each against the size before any of them: two commits racing
// past one check could each fit alone and overshoot together, by up to the
// concurrency times the largest message.
//
// The occupied size is read before quotaMu is taken, so two callers can share
// one view of it -- but the reservation itself is made under the lock and
// against the current reserved total, which is what makes the second caller
// see the first one's claim.
func (s *Spool) reserveQuota(n int64) error {
	s.mu.Lock()
	live := s.indexBytes
	s.mu.Unlock()

	s.failedMu.Lock()
	failed := s.failedBytes
	s.failedMu.Unlock()

	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	if s.maxQuotaBytes > 0 && live+failed+s.reserved+n > s.maxQuotaBytes {
		return ErrQuotaExceeded
	}
	s.reserved += n
	return nil
}

func (s *Spool) releaseQuota(n int64) {
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	s.reserved -= n
}

// QuotaWarning reports whether the spool has reached limits.spool_warn_percent
// of its configured quota. over is false whenever no quota or no warning
// threshold is configured. It does no logging itself and mutates nothing:
// this package holds no logger, so the caller (the delivery manager) is
// responsible for reporting the transition.
func (s *Spool) QuotaWarning() (used, quota int64, over bool) {
	s.quotaMu.Lock()
	quota, warnPercent := s.maxQuotaBytes, s.warnQuotaPercent
	s.quotaMu.Unlock()

	if quota <= 0 || warnPercent <= 0 {
		return 0, quota, false
	}
	used = s.usedBytes()
	// quota may be math.MaxInt64 (SetQuota clamps an oversized config value
	// to it), so quota*warnPercent could overflow. Dividing quota first
	// instead cannot overflow and loses at most 99 bytes of precision,
	// irrelevant for a threshold measured in gigabytes.
	over = used >= quota/100*int64(warnPercent)
	return used, quota, over
}

// SetQuota configures the maximum spool size and warning threshold. A maxGB of
// zero or less means no quota; the caller is expected to have rejected a
// negative value at configuration load time, and the multiplication is done in
// int64 so that a large value cannot wrap into one.
func (s *Spool) SetQuota(maxGB int, warnPercent int) {
	const gib = 1024 * 1024 * 1024
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
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
