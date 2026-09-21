// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package ratelimit

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// Both suites this package replaced asserted the same three properties, one
// of them ignoring the wait. They are merged here rather than kept apart,
// since there is now one implementation to hold to them.

func TestZeroLimitIsUnlimited(t *testing.T) {
	l := New()
	now := time.Now()
	for i := 0; i < 1000; i++ {
		if _, ok := l.Allow("m365", 0, now); !ok {
			t.Fatal("a key without a limit was throttled")
		}
	}
	// A negative limit is a mistyped minus sign, not a ceiling of -1.
	// config.Validate refuses one; this is what it would mean if it got here.
	if _, ok := l.Allow("m365", -5, now); !ok {
		t.Fatal("a negative limit was treated as a ceiling")
	}
	// Nothing was ever counted, so no bucket was allocated either.
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	if n != 0 {
		t.Errorf("an unlimited key allocated %d bucket(s)", n)
	}
}

func TestThrottlesAtTheLimitAndRefillsAfterAMinute(t *testing.T) {
	l := New()
	now := time.Now()

	for i := 0; i < 3; i++ {
		if _, ok := l.Allow("c", 3, now); !ok {
			t.Fatalf("token %d denied within the limit", i)
		}
	}
	wait, ok := l.Allow("c", 3, now)
	if ok {
		t.Fatal("the fourth token was handed out over a limit of three")
	}
	if wait < minWait || wait > window {
		t.Fatalf("wait = %v, want between %v and %v", wait, minWait, window)
	}
	// Just short of the window the bucket is still empty; at the window it is
	// full again. Both halves, so a refill that fired early or not at all
	// fails here.
	if _, ok := l.Allow("c", 3, now.Add(window-time.Millisecond)); ok {
		t.Error("the bucket refilled before the window was up")
	}
	if _, ok := l.Allow("c", 3, now.Add(window)); !ok {
		t.Fatal("the bucket did not refill after the window")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New()
	now := time.Now()
	if _, ok := l.Allow("m365", 1, now); !ok {
		t.Fatal("the first key was throttled immediately")
	}
	if _, ok := l.Allow("m365", 1, now); ok {
		t.Fatal("the first key was not throttled after its only token")
	}
	if _, ok := l.Allow("partner", 1, now); !ok {
		t.Fatal("one exhausted key throttled another")
	}
}

// The wait is what the dispatcher defers a message by, so it has to shrink as
// the window runs out rather than always report a whole minute -- and it must
// never reach zero, or the deferral becomes a spin.
func TestWaitShrinksTowardsTheEndOfTheWindowButNeverHitsZero(t *testing.T) {
	l := New()
	now := time.Now()
	if _, ok := l.Allow("r", 1, now); !ok {
		t.Fatal("the only token was refused")
	}

	early, _ := l.Allow("r", 1, now.Add(10*time.Second))
	late, _ := l.Allow("r", 1, now.Add(50*time.Second))
	if !(early > late) {
		t.Errorf("wait did not shrink across the window: %v then %v", early, late)
	}
	atTheEnd, ok := l.Allow("r", 1, now.Add(window-time.Nanosecond))
	if ok {
		t.Fatal("the bucket refilled a nanosecond early")
	}
	if atTheEnd < minWait {
		t.Errorf("wait at the end of the window = %v, want at least %v", atTheEnd, minWait)
	}
}

// Both callers share one Limiter across goroutines: every listener session
// hits the same one, and so does every delivery worker.
func TestConcurrentAllowHandsOutExactlyTheLimit(t *testing.T) {
	l := New()
	now := time.Now()
	const limit = 50
	const callers = 200

	var wg sync.WaitGroup
	granted := make([]bool, callers)
	for i := 0; i < callers; i++ {
		wg.Go(func() {
			_, ok := l.Allow("shared", limit, now)
			granted[i] = ok
		})
	}
	wg.Wait()

	n := 0
	for _, ok := range granted {
		if ok {
			n++
		}
	}
	if n != limit {
		t.Errorf("%d of %d callers were allowed, want exactly %d", n, callers, limit)
	}
}

// Buckets are created on demand and never dropped, which is why the doc
// comment requires a configuration-bounded key space. Pinned so that a future
// change adding eviction has to come with a decision about what it costs the
// two callers, rather than arriving by accident.
func TestBucketsAreKeptPerKey(t *testing.T) {
	l := New()
	now := time.Now()
	for i := 0; i < 100; i++ {
		l.Allow("client-"+strconv.Itoa(i), 1, now)
	}
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	if n != 100 {
		t.Errorf("the limiter holds %d buckets for 100 keys", n)
	}
}
