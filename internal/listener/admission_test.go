// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"strconv"
	"testing"
)

func TestConnCounterEnforcesLimit(t *testing.T) {
	c := newConnCounter()
	for i := 0; i < 2; i++ {
		if !c.acquire("k", 2) {
			t.Fatalf("slot %d denied within the limit", i)
		}
	}
	if c.acquire("k", 2) {
		t.Fatal("limit was not enforced")
	}
	c.release("k", 2)
	if !c.acquire("k", 2) {
		t.Fatal("a released slot was not reusable")
	}
	if !c.acquire("unlimited", 0) {
		t.Fatal("a limit of zero must mean unlimited")
	}
}

// TestConnCounterDoesNotGrowPerAddress guards the unmatched-source path: its
// keys are remote addresses, so an entry left behind at zero would let any
// source grow this map without bound.
func TestConnCounterDoesNotGrowPerAddress(t *testing.T) {
	c := newConnCounter()
	for i := 0; i < 1000; i++ {
		key := "unmatched:198.51.100." + strconv.Itoa(i%256) + ":" + strconv.Itoa(i)
		if !c.acquire(key, unmatchedMaxConns) {
			t.Fatalf("acquire %d denied", i)
		}
		c.release(key, unmatchedMaxConns)
	}
	c.mu.Lock()
	n := len(c.n)
	c.mu.Unlock()
	if n != 0 {
		t.Fatalf("counter retained %d entries after every connection closed", n)
	}
}

// The two key spaces the counter holds must not meet. A client may legally be
// named "unmatched:<addr>" -- config.ValidName permits any printable ASCII
// without a quote or backslash -- and without a prefix on both sides such a
// client would share its connection budget with the unmatched source at that
// address, which is a budget of two.
func TestConnCounterKeySpacesCannotCollide(t *testing.T) {
	const addr = "198.51.100.7:2525"
	if connKeyClient("unmatched:"+addr) == connKeyUnmatched(addr) {
		t.Fatal("a client named after an unmatched key shares its budget")
	}

	c := newConnCounter()
	// The unmatched source exhausts its own cap; the identically named client
	// must still get its own slots.
	for i := 0; i < unmatchedMaxConns; i++ {
		if !c.acquire(connKeyUnmatched(addr), unmatchedMaxConns) {
			t.Fatalf("unmatched slot %d denied within its cap", i)
		}
	}
	if c.acquire(connKeyUnmatched(addr), unmatchedMaxConns) {
		t.Fatal("the unmatched cap was not enforced")
	}
	if !c.acquire(connKeyClient("unmatched:"+addr), unmatchedMaxConns) {
		t.Fatal("the client was refused a slot the unmatched source had used up")
	}
}
