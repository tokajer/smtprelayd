// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package delivery

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// A smarthost that accepted the body owns the message even if the session
// then fails. attempt has to read that as delivered: leaving the copy queued
// means the next attempt sends it a second time, and the operator sees a
// duplicate they cannot explain from the log.
func TestAttemptTreatsAnUncleanCloseAfterAcceptanceAsDelivered(t *testing.T) {
	f := startDroppingSmarthost(t)
	m, sp, st := managerAgainst(t, f)
	id, meta := queueOne(t, sp, st, time.Hour)

	m.attempt(context.Background(), meta)

	if sp.Has(id) {
		t.Error("the message is still queued although the smarthost accepted it; it would be delivered twice")
	}
	if got := statusOf(t, st, id); got != "delivered" {
		t.Errorf("journal status %q, want delivered", got)
	}
}

// hangingSmarthost answers every command but never the body, so an attempt
// against it occupies its worker slot until the delivery deadline.
func hangingSmarthost(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				say := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }
				say("220 hanging ESMTP")
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.ToUpper(strings.TrimSpace(line))
					switch {
					case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
						say("250 hanging")
					case strings.HasPrefix(cmd, "DATA"):
						say("354 end with <CRLF>.<CRLF>")
						for {
							l, err := br.ReadString('\n')
							if err != nil {
								return
							}
							if strings.TrimRight(l, "\r\n") == "." {
								break
							}
						}
						select {} // never answers the body
					default:
						say("250 2.0.0 ok")
					}
				}
			}(conn)
		}
	}()
	h, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return h, n
}

// Claim returns the globally oldest due message whatever route it belongs to,
// and there is one dispatcher, so a route whose concurrency budget is full
// must not be waited on: doing so holds every other route behind the worst
// smarthost for as long as an attempt can last, which is
// limits.delivery_timeout_sec -- 600s by default.
//
// Measured before the fix: the healthy route's message went out in 100ms
// beside a working neighbour and was still queued after 8s beside this one.
func TestASaturatedRouteDoesNotStallTheOtherRoutes(t *testing.T) {
	slowHost, slowPort := hangingSmarthost(t)
	healthy := startFakeSmarthost(t, "250 2.0.0 accepted")
	healthyHost, healthyPort := healthy.hostPort(t)

	cfg := &config.Config{
		Service: config.Service{Hostname: "relay.test"},
		Queue:   config.Queue{MaxLifetimeHours: 96, RetryScheduleMin: []int{1, 5}},
		Limits:  config.Limits{DeliveryTimeoutSec: 30},
		Bounce:  config.Bounce{DigestMinutes: 15, MaxPerHour: 10},
		Routes: []config.Route{
			// One slot, so the second message for this route finds it full.
			{Name: "slow", Host: slowHost, Port: slowPort, TLS: "none", Auth: "none", MaxConcurrent: 1},
			{Name: "healthy", Host: healthyHost, Port: healthyPort, TLS: "none", Auth: "none", MaxConcurrent: 4},
		},
	}
	sp, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir(), discardLog(), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	m, err := New(cfg, sp, discardLog(), st)
	if err != nil {
		t.Fatal(err)
	}

	// Both messages for the stuck route are older, so Claim offers them
	// first and the healthy route's message sits behind them.
	base := time.Now().UTC().Add(-time.Hour)
	enqueue := func(route string, at time.Time) spool.ID {
		t.Helper()
		id, err := sp.Enqueue(spool.Envelope{
			From: "device@example.at", To: []string{"ops@example.net"},
			Client: "printers", Route: route, Received: at,
		}, strings.NewReader("Subject: t\r\n\r\nbody\r\n"), 0, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	enqueue("slow", base)
	enqueue("slow", base.Add(time.Second))
	healthyID := enqueue("healthy", base.Add(2*time.Second))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if !sp.Has(healthyID) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the healthy route's message was never dispatched: a saturated route held the dispatcher")
}
