// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package delivery

import (
	"testing"
	"time"
)

func TestRouteLimiterUnlimited(t *testing.T) {
	r := newRouteLimiter()
	now := time.Now()
	for i := 0; i < 1000; i++ {
		if _, ok := r.allow("m365", 0, now); !ok {
			t.Fatal("a route without a limit was throttled")
		}
	}
}

func TestRouteLimiterThrottlesAndRefills(t *testing.T) {
	r := newRouteLimiter()
	now := time.Now()

	for i := 0; i < 3; i++ {
		if _, ok := r.allow("m365", 3, now); !ok {
			t.Fatalf("message %d was throttled inside the limit", i)
		}
	}
	wait, ok := r.allow("m365", 3, now)
	if ok {
		t.Fatal("the fourth message was not throttled")
	}
	if wait < time.Second || wait > time.Minute {
		t.Fatalf("wait = %v, want between a second and a minute", wait)
	}
	if _, ok := r.allow("m365", 3, now.Add(time.Minute)); !ok {
		t.Fatal("the bucket did not refill after a minute")
	}
}

func TestRouteLimiterIsPerRoute(t *testing.T) {
	r := newRouteLimiter()
	now := time.Now()
	if _, ok := r.allow("m365", 1, now); !ok {
		t.Fatal("first route throttled immediately")
	}
	if _, ok := r.allow("partner", 1, now); !ok {
		t.Fatal("one exhausted route throttled another")
	}
}
