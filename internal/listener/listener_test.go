// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testSet(t *testing.T, address string) *Set {
	t.Helper()
	cfg := &config.Config{
		Listeners: []config.Listener{{Name: "test", Address: address, TLS: "none"}},
		Limits:    config.Limits{MaxConnections: 10},
	}
	set, err := New(cfg, nil, discardLog(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return set
}

// TestBindFailsOnAddressAlreadyInUse is the regression test for the Windows
// startup-reporting fix: Bind must fail synchronously, before Run ever
// starts accepting, so a caller (cmd/smtprelayd's winProgram.Start) can
// report the failure instead of only logging it.
func TestBindFailsOnAddressAlreadyInUse(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupying a port: %v", err)
	}
	defer occupied.Close()

	set := testSet(t, occupied.Addr().String())
	if err := set.Bind(); err == nil {
		t.Fatal("Bind succeeded on an address another listener already holds")
	}
}

// TestBindThenRunAcceptsConnections confirms the split still binds and
// serves, since Bind and Run used to be one method (Serve) and nothing else
// in this package exercises that path end to end.
func TestBindThenRunAcceptsConnections(t *testing.T) {
	set := testSet(t, "127.0.0.1:0")
	if err := set.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	addr := set.servers[0].ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		set.Run(ctx)
		close(done)
	}()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

// TestCloseDoesNotRaceAcceptedConnections is the regression test for the
// wg.Add/wg.Wait race stopAccepting's doc comment describes: a connection
// Accept had already returned right as shutdown began must never reach
// wg.Add after Set.Close's wg.Wait has started. Dialing continuously while
// cancelling gives -race a real chance to land in that window; run with
// -race, which the CI vet/test job always does.
func TestCloseDoesNotRaceAcceptedConnections(t *testing.T) {
	set := testSet(t, "127.0.0.1:0")
	if err := set.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	addr := set.servers[0].ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		set.Run(ctx)
		close(done)
	}()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	}

	time.Sleep(20 * time.Millisecond)
	cancel()
	close(stop)
	wg.Wait()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}
