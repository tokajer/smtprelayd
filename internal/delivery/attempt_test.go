// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package delivery

import (
	"bufio"
	"context"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/bounce"
	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/queueid"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// attempt decides what becomes of every queued message and was entirely
// unexecuted: its pure helpers are covered, the wiring between them was not.
// There is no seam to inject a smarthost through, and adding one only to test
// would be a production change made for the test's benefit -- but the route's
// host and port come from the configuration, so pointing them at a scripted
// server on loopback exercises the real path instead.

// fakeSmarthost speaks just enough SMTP to drive one message to a chosen
// verdict. dataReply is the response to the body, which is where a smarthost
// says 250, 550 or 451.
type fakeSmarthost struct {
	ln        net.Listener
	dataReply string
	// dropAfterData hangs up once the body has been answered, without
	// waiting for QUIT. Exchange does this, and so does any connection that
	// dies in the gap between the 250 and the goodbye.
	dropAfterData bool
	// rcptReplies answers the nth RCPT with rcptReplies[n-1] when one is
	// given, so a message can be driven to a partial acceptance. An index
	// past the end falls back to accepting.
	rcptReplies []string
	rcptSeen    int
}

// startSelectiveSmarthost accepts the body but answers each RCPT from
// rcptReplies, which is how a distribution list with one dead mailbox
// behaves.
func startSelectiveSmarthost(t *testing.T, rcptReplies ...string) *fakeSmarthost {
	t.Helper()
	return startSmarthost(t, &fakeSmarthost{
		dataReply:   "250 2.0.0 accepted",
		rcptReplies: rcptReplies,
	})
}

func startFakeSmarthost(t *testing.T, dataReply string) *fakeSmarthost {
	t.Helper()
	return startSmarthost(t, &fakeSmarthost{dataReply: dataReply})
}

// startDroppingSmarthost accepts the message and then vanishes.
func startDroppingSmarthost(t *testing.T) *fakeSmarthost {
	t.Helper()
	return startSmarthost(t, &fakeSmarthost{dataReply: "250 2.0.0 accepted", dropAfterData: true})
}

func startSmarthost(t *testing.T, f *fakeSmarthost) *fakeSmarthost {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(conn)
		}
	}()
	return f
}

func (f *fakeSmarthost) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	say := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }

	say("220 fake ESMTP")
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			// Single line, so net/smtp sees no extensions to negotiate.
			say("250 fake")
		case strings.HasPrefix(cmd, "MAIL"):
			say("250 2.1.0 sender ok")
		case strings.HasPrefix(cmd, "RCPT"):
			f.rcptSeen++
			if i := f.rcptSeen - 1; i < len(f.rcptReplies) {
				say(f.rcptReplies[i])
				continue
			}
			say("250 2.1.5 recipient ok")
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
			say(f.dataReply)
			if f.dropAfterData {
				return
			}
		case strings.HasPrefix(cmd, "QUIT"):
			say("221 2.0.0 bye")
			return
		case strings.HasPrefix(cmd, "RSET"), strings.HasPrefix(cmd, "NOOP"):
			say("250 2.0.0 ok")
		default:
			say("500 5.5.1 unrecognised")
		}
	}
}

func (f *fakeSmarthost) hostPort(t *testing.T) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

// managerAgainst wires a Manager whose only route is the scripted server.
func managerAgainst(t *testing.T, f *fakeSmarthost) (*Manager, *spool.Spool, *store.Store, *bounce.Notifier, *metrics.Registry) {
	t.Helper()
	host, port := f.hostPort(t)
	cfg := &config.Config{
		Service: config.Service{Hostname: "relay.test"},
		Queue:   config.Queue{MaxLifetimeHours: 96, RetryScheduleMin: []int{1, 5}},
		Limits:  config.Limits{DeliveryTimeoutSec: 20},
		Bounce: config.Bounce{
			Sender: "bounce@example.at", NotifyRoute: "smarthost",
			DigestMinutes: 15, MaxPerHour: 10, Notify: []string{"ops@example.at"},
		},
		Routes: []config.Route{{
			Name: "smarthost", Host: host, Port: port,
			TLS: "none", Auth: "none", MaxConcurrent: 1,
		}},
	}
	sp, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "history.db"), discardLog(), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	reg := testRegistry(cfg, sp)
	notifier := bounce.New(cfg, sp, st, reg, discardLog())
	m := New(cfg, sp, st, reg, nil, notifier, discardLog())
	return m, sp, st, notifier, reg
}

// queueOne spools a message and journals it. The journal row has to exist
// first: store.RecordAttempt refuses an unknown queue ID, and attempt
// deliberately ignores that error, so without this the outcome would be
// written nowhere and the assertions would pass against an empty table.
func queueOne(t *testing.T, sp *spool.Spool, st *store.Store, lifetime time.Duration) (queueid.ID, *spool.Meta) {
	t.Helper()
	now := time.Now().UTC()
	env := spool.Envelope{From: "device@example.at", To: []string{"ops@example.net"},
		Origin: "printers", Route: "smarthost", Received: now}
	id, err := sp.Enqueue(env, strings.NewReader("Subject: t\r\n\r\nbody\r\n"), 0, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordMessage(store.MessageRecord{
		QueueID: id, Origin: "printers", Route: "smarthost",
		EnvelopeFrom: "device@example.at", Recipients: []string{"ops@example.net"},
		Listener: "l", RemoteAddr: "127.0.0.1", ReceivedAt: now, ExpiresAt: now.Add(lifetime),
	}); err != nil {
		t.Fatal(err)
	}
	meta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("nothing to claim")
	}
	return id, meta
}

func statusOf(t *testing.T, st *store.Store, id queueid.ID) string {
	t.Helper()
	msg, err := st.FindMessageByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		t.Fatalf("no journal row for %s", id)
	}
	return msg.Status
}

func TestAttemptDeliveredRemovesTheMessage(t *testing.T) {
	f := startFakeSmarthost(t, "250 2.0.0 accepted")
	m, sp, st, _, _ := managerAgainst(t, f)
	id, meta := queueOne(t, sp, st, time.Hour)

	m.attempt(context.Background(), meta)

	if sp.Has(id) {
		t.Error("a delivered message is still in the spool")
	}
	if got := statusOf(t, st, id); got != "delivered" {
		t.Errorf("journal status %q, want delivered", got)
	}
}

// A 5xx on the body is the smarthost's final word, so the message is moved
// aside rather than retried.
func TestAttemptPermanentFailureMovesTheMessageAside(t *testing.T) {
	f := startFakeSmarthost(t, "550 5.1.1 unknown recipient")
	m, sp, st, notifier, _ := managerAgainst(t, f)
	id, meta := queueOne(t, sp, st, time.Hour)

	m.attempt(context.Background(), meta)

	// Has stays true on purpose -- it reports "the spool still holds files
	// for this", and a failed message keeps them under spool/failed so the
	// quota still counts them. What must change is that it left the live
	// queue and will not be tried again.
	if sp.Len() != 0 {
		t.Errorf("the live queue still holds %d message(s) after a permanent failure", sp.Len())
	}
	if _, ok := sp.Claim(time.Now().Add(24 * time.Hour)); ok {
		t.Error("a permanently failed message was handed out for another attempt")
	}
	if got := statusOf(t, st, id); got != "bounced" {
		t.Errorf("journal status %q, want bounced", got)
	}
	// A real client failure is what the bounce digest exists to report.
	if got := notifier.Pending(); got != 1 {
		t.Errorf("pending bounce notifications = %d, want 1", got)
	}
}

// A 4xx is the smarthost asking for a retry: the message stays queued, the
// attempt counter moves, and the next try is scheduled off the configured
// schedule rather than immediately.
func TestAttemptTemporaryFailureDefersWithBackoff(t *testing.T) {
	f := startFakeSmarthost(t, "451 4.3.0 try again later")
	m, sp, st, _, _ := managerAgainst(t, f)
	id, meta := queueOne(t, sp, st, time.Hour)

	m.attempt(context.Background(), meta)

	if !sp.Has(id) {
		t.Fatal("a temporarily failed message was dropped from the queue")
	}
	if meta.Attempts != 1 {
		t.Errorf("attempts = %d after one try, want 1", meta.Attempts)
	}
	// RetryScheduleMin starts at 1 minute, and attempt 1 takes the first entry.
	if want := time.Now().Add(time.Minute); meta.NextAttempt.Sub(want) > 30*time.Second || want.Sub(meta.NextAttempt) > 30*time.Second {
		t.Errorf("next attempt at %v, want about %v (the first schedule entry)", meta.NextAttempt, want)
	}
	if meta.LastError == "" {
		t.Error("the deferral recorded no reason, so the dashboard shows none")
	}
	if got := statusOf(t, st, id); got != "deferred" {
		t.Errorf("journal status %q, want deferred", got)
	}
}

// A queued message whose route was removed from the configuration between
// being queued and being attempted must still get a journal row -- the two
// paths that fail before ever reaching the smarthost used to leave none,
// which made the dashboard show nothing for a message that provably existed.
func TestAttemptUnknownRouteRecordsAPermanentJournalRow(t *testing.T) {
	f := startFakeSmarthost(t, "250 2.0.0 accepted")
	m, sp, st, _, _ := managerAgainst(t, f)
	id, meta := queueOne(t, sp, st, time.Hour)
	meta.Envelope.Route = "no-such-route"

	m.attempt(context.Background(), meta)

	msg, err := st.FindMessageByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil || len(msg.Attempts) != 1 || msg.Attempts[0].Class != store.ClassPermanent {
		t.Fatalf("journal row = %+v, want exactly one attempt of class permanent", msg)
	}
	if !sp.Has(id) {
		t.Error("a message failed for an unknown route must still be kept under spool/failed")
	}
}

// A context cancelled mid-attempt -- shutdown racing an in-flight send -- must
// not be recorded as a delivery attempt: the smarthost connection failing
// because the context expired is not the smarthost saying "try later", and
// counting it would burn a retry step and write a spurious journal row on
// every restart that catches a send in flight.
func TestAttemptCancelledContextLeavesNoAttemptOrJournalRow(t *testing.T) {
	f := startFakeSmarthost(t, "250 2.0.0 accepted")
	m, sp, st, _, _ := managerAgainst(t, f)
	id, meta := queueOne(t, sp, st, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m.attempt(ctx, meta)

	if meta.Attempts != 0 {
		t.Errorf("attempts = %d after a cancelled attempt, want 0", meta.Attempts)
	}
	msg, err := st.FindMessageByID(id)
	if err != nil {
		t.Fatal(err)
	}
	// queueOne already wrote the journal row via RecordMessage, so a nil
	// result here means the row vanished, not that there was never one to
	// check -- either way this must not pass silently.
	if msg == nil {
		t.Fatal("no journal row at all for a message that was queued and journalled before the attempt")
	}
	if len(msg.Attempts) != 0 {
		t.Errorf("journal holds %d attempt row(s) for a cancelled attempt, want 0", len(msg.Attempts))
	}
	if !sp.Has(id) {
		t.Error("a cancelled attempt must leave the message in the spool")
	}
	// The lease queueOne's Claim took must be cleared, or the message can
	// never be attempted again.
	claimed, ok := sp.Claim(time.Now())
	if !ok || claimed.ID != id {
		t.Errorf("message not claimable after a cancelled attempt: got %v, %v -- the lease was not cleared", claimed, ok)
	}
}

// Past its lifetime a message is given up on even though the failure is
// retryable: queue.max_lifetime_hours is what stops a permanently unreachable
// smarthost from holding mail forever.
func TestAttemptPastExpiryIsGivenUpOn(t *testing.T) {
	f := startFakeSmarthost(t, "451 4.3.0 try again later")
	m, sp, st, _, _ := managerAgainst(t, f)
	id, meta := queueOne(t, sp, st, time.Hour)
	meta.Expires = time.Now().Add(-time.Minute)

	m.attempt(context.Background(), meta)

	if sp.Len() != 0 {
		t.Errorf("the live queue still holds %d message(s) after expiry", sp.Len())
	}
	if _, ok := sp.Claim(time.Now().Add(24 * time.Hour)); ok {
		t.Error("an expired message was handed out for another attempt")
	}
	if got := statusOf(t, st, id); got != "bounced" {
		t.Errorf("journal status %q, want bounced", got)
	}
}

// Two paths fail a message before it is ever offered to a smarthost --
// dispatchOne's own unknown-route check, ahead of claiming a worker slot, and
// send's OpenBody failure -- and both go through failUnsendable. Both must
// still leave the counter and the journal in the same state fail() leaves
// them in for any other permanent failure, or an operator sees a message
// that provably existed and produced no history row at all.
func TestUnsendablePathsRecordAPermanentJournalRow(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, m *Manager, sp *spool.Spool, meta *spool.Meta)
	}{
		{
			name: "dispatchOne: unknown route",
			run: func(t *testing.T, m *Manager, sp *spool.Spool, meta *spool.Meta) {
				meta.Envelope.Route = "no-such-route"
				if ok := m.dispatchOne(context.Background(), meta, map[string]bool{}); !ok {
					t.Fatal("dispatchOne reported cancellation on a live context")
				}
			},
		},
		{
			name: "send: unreadable body",
			run: func(t *testing.T, m *Manager, sp *spool.Spool, meta *spool.Meta) {
				// The metadata stays in meta (the caller's own copy); only the
				// body backing it is gone, which is what OpenBody sees.
				if err := sp.Remove(meta.ID); err != nil {
					t.Fatal(err)
				}
				route, ok := m.cfg.Route(meta.Envelope.Route)
				if !ok {
					t.Fatal("route not found")
				}
				if _, ok := m.send(context.Background(), discardLog(), route, meta); ok {
					t.Fatal("send reported success for an unreadable body")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := startFakeSmarthost(t, "250 2.0.0 accepted")
			m, sp, st, _, _ := managerAgainst(t, f)
			id, meta := queueOne(t, sp, st, time.Hour)

			tc.run(t, m, sp, meta)

			if meta.Attempts != 1 {
				t.Errorf("Attempts = %d, want 1", meta.Attempts)
			}
			msg, err := st.FindMessageByID(id)
			if err != nil {
				t.Fatal(err)
			}
			if msg == nil || len(msg.Attempts) != 1 || msg.Attempts[0].Class != store.ClassPermanent {
				t.Fatalf("journal row = %+v, want exactly one attempt of class permanent", msg)
			}
		})
	}
}
