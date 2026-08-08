// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"testing"
	"time"
)

// TestReadDeadlineClampedToSession covers the unmatched-source path: the per
// command deadline is refreshed by every NOOP, so without the clamp a source
// that simply stops sending would outlive its session budget inside one
// blocking read.
func TestReadDeadlineClampedToSession(t *testing.T) {
	s := &session{deadline: time.Now().Add(2 * time.Second)}
	if got := s.readDeadline(60); got.After(s.deadline) {
		t.Fatalf("read deadline %v outlives the session deadline %v", got, s.deadline)
	}
}

func TestReadDeadlineUnclampedWithoutSessionLimit(t *testing.T) {
	// An allowlisted client has no session deadline and must keep the full
	// per command timeout, so a slow device is not disconnected mid-transfer.
	s := &session{}
	got := s.readDeadline(60)
	if got.Before(time.Now().Add(50 * time.Second)) {
		t.Fatalf("read deadline %v was shortened without a session deadline", got)
	}
}

func TestReadDeadlineUsesSessionLimitWhenShorter(t *testing.T) {
	s := &session{deadline: time.Now().Add(time.Hour)}
	// A session budget longer than the command timeout must not extend it.
	if got := s.readDeadline(1); got.After(time.Now().Add(10 * time.Second)) {
		t.Fatalf("session deadline extended the per command timeout to %v", got)
	}
}

func TestTimeoutFallsBackOnNonPositiveValues(t *testing.T) {
	s := &session{}
	for _, sec := range []int{0, -1} {
		if d := s.timeout(sec); d != 60*time.Second {
			t.Errorf("timeout(%d) = %v, want the 60s fallback", sec, d)
		}
	}
}
