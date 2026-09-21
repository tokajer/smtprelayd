// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"errors"
	"testing"
	"time"
)

// The SCM gives a service 30 seconds to report SERVICE_RUNNING and kills it
// otherwise -- and windowsServiceConfig asks for a restart on failure, so a
// start that is merely slow becomes an endless restart loop. Start used to
// block on the ready signal without a bound, and what makes it slow is
// spool.Open: 8.7 seconds for 100 000 queued messages on a Windows VM, rising
// faster than linearly. A backlog left by a smarthost outage was therefore
// enough to stop the service from ever starting again.
func TestAwaitReadyGivesUpBeforeTheSCMDoes(t *testing.T) {
	if readyWait >= 30*time.Second {
		t.Fatalf("readyWait is %v; the SCM's own limit is 30s, so this never fires", readyWait)
	}

	never := make(chan error) // a startup still in flight
	start := time.Now()
	err, settled := awaitReady(never, 50*time.Millisecond)
	elapsed := time.Since(start)

	if settled {
		t.Error("a startup that has not finished was reported as settled")
	}
	if err != nil {
		t.Errorf("an unfinished startup reported error %v; it has no verdict yet", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("awaitReady waited %v past its limit", elapsed)
	}
}

// The half of blocking that was worth keeping: a startup that fails fast --
// a bad configuration, a bound port, a rejected credential -- is still
// reported to the SCM as a failed start rather than as a running service.
func TestAwaitReadyReturnsAFastFailure(t *testing.T) {
	want := errors.New("configuration is not valid")
	ready := make(chan error, 1)
	ready <- want

	err, settled := awaitReady(ready, 5*time.Second)
	if !settled {
		t.Fatal("a verdict that was already available was not picked up")
	}
	if !errors.Is(err, want) {
		t.Errorf("got %v, want the startup error %v", err, want)
	}
}

// And a successful start still reports success.
func TestAwaitReadyReturnsSuccess(t *testing.T) {
	ready := make(chan error, 1)
	ready <- nil
	if err, settled := awaitReady(ready, 5*time.Second); !settled || err != nil {
		t.Errorf("a successful start reported (%v, settled=%v)", err, settled)
	}
}
