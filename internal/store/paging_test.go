// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package store

import (
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"
)

// An offset past the end of the result set costs SQLite a walk of the whole
// set before it can return nothing. internal/api clamped its cursor for that
// reason; the dashboard's parseOffset never did, and this is the choke point
// both of them reach, so the bound belongs here.
func TestPagingIsClampedAtBothEnds(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		limit, offset         int
		wantLimit, wantOffset int
	}{
		{"defaults", 0, 0, 100, 0},
		// SQLite reads a negative LIMIT as "no limit", and FindBounces tested
		// for == 0, so one used to pass straight through to the query.
		{"negative limit is not SQLite's no-limit", -1, 0, 100, 0},
		{"limit capped", 50000, 0, 1000, 0},
		{"negative offset resets", 50, -5, 50, 0},
		{"huge offset resets", 50, 1 << 62, 50, 0},
		{"offset at the bound survives", 50, MaxOffset, 50, MaxOffset},
		{"offset past the bound resets", 50, MaxOffset + 1, 50, 0},
		{"ordinary paging untouched", 50, 200, 50, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotLimit, gotOffset := clampPaging(tc.limit, tc.offset)
			if gotLimit != tc.wantLimit || gotOffset != tc.wantOffset {
				t.Errorf("clampPaging(%d, %d) = (%d, %d), want (%d, %d)",
					tc.limit, tc.offset, gotLimit, gotOffset, tc.wantLimit, tc.wantOffset)
			}
		})
	}
}

// The clamp has to be reached through the real queries, not only unit-tested,
// and by all three of them: the dashboard and the API between them use every
// one.
func TestListQueriesClampAHugeOffset(t *testing.T) {
	s, err := Open(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UTC()
	const rows = 5
	for i := 0; i < rows; i++ {
		id := fmt.Sprintf("QAAAAAAAAAAAAA%02d", i)
		if err := s.RecordMessage(MessageRecord{
			QueueID: id, Client: "c", Route: "r",
			EnvelopeFrom: "a@b.at", Recipients: `["x@y.at"]`, Listener: "l",
			RemoteAddr: "127.0.0.1", ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordAttempt(id, 1, 550, "rejected", "permanent", nil); err != nil {
			t.Fatal(err)
		}
	}

	const huge = 1 << 62

	got, _, err := s.FindMessages(MessageFilter{Limit: 10, Offset: huge})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != rows {
		t.Errorf("FindMessages returned %d rows for a clamped offset, want the first page of %d", len(got), rows)
	}

	bounces, _, err := s.FindBounces(BounceFilter{Limit: 10, Offset: huge})
	if err != nil {
		t.Fatal(err)
	}
	if len(bounces) != rows {
		t.Errorf("FindBounces returned %d rows for a clamped offset, want %d", len(bounces), rows)
	}

	summaries, _, err := s.FindBounceSummaries(BounceFilter{Limit: 10, Offset: huge})
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != rows {
		t.Errorf("FindBounceSummaries returned %d rows for a clamped offset, want %d", len(summaries), rows)
	}
}

// All three paged queries fetch one row past the limit to answer "is there
// another page", and that row is bookkeeping. It used to be returned, with
// each caller expected to remember to cut it off; the one that forgot would
// have rendered a page one row too long, which nobody reports. The contract
// is now the same for all three and the extra row never leaves the store.
func TestPagedQueriesReturnTheLimitAndReportMore(t *testing.T) {
	s, err := Open(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now().UTC()
	const rows = 5
	for i := 0; i < rows; i++ {
		id := fmt.Sprintf("QBBBBBBBBBBBBB%02d", i)
		if err := s.RecordMessage(MessageRecord{
			QueueID: id, Client: "c", Route: "r",
			EnvelopeFrom: "a@b.at", Recipients: `["x@y.at"]`, Listener: "l",
			RemoteAddr: "127.0.0.1", ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordAttempt(id, 1, 550, "rejected", "permanent", nil); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name    string
		query   func(limit int) (int, bool, error)
		wantLen int
	}{
		{"FindMessages", func(limit int) (int, bool, error) {
			got, more, err := s.FindMessages(MessageFilter{Limit: limit})
			return len(got), more, err
		}, rows},
		{"FindBounces", func(limit int) (int, bool, error) {
			got, more, err := s.FindBounces(BounceFilter{Limit: limit})
			return len(got), more, err
		}, rows},
		{"FindBounceSummaries", func(limit int) (int, bool, error) {
			got, more, err := s.FindBounceSummaries(BounceFilter{Limit: limit})
			return len(got), more, err
		}, rows},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A short page: the limit exactly, and a promise of more.
			n, more, err := tc.query(rows - 2)
			if err != nil {
				t.Fatal(err)
			}
			if n != rows-2 {
				t.Errorf("returned %d rows for limit %d; the extra lookahead row escaped", n, rows-2)
			}
			if !more {
				t.Error("hasMore is false although rows remain")
			}
			// The last page: everything, and no promise of more.
			n, more, err = tc.query(rows)
			if err != nil {
				t.Fatal(err)
			}
			if n != tc.wantLen {
				t.Errorf("returned %d rows, want %d", n, tc.wantLen)
			}
			if more {
				t.Error("hasMore is true on the last page")
			}
		})
	}
}
