// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package delivery

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testManager(t *testing.T) (*Manager, *spool.Spool) {
	t.Helper()
	cfg := &config.Config{
		Queue: config.Queue{MaxLifetimeHours: 96, RetryScheduleMin: []int{1}},
		Bounce: config.Bounce{
			Sender: "bounce@example.at", NotifyRoute: "m365",
			DigestMinutes: 15, MaxPerHour: 10, Notify: []string{"ops@example.at"},
		},
		Routes: []config.Route{{Name: "m365", Auth: "none", MaxConcurrent: 1}},
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
	return m, sp
}

// TestFailRecordsRealClientFailureButNotANotificationsOwn is the regression
// test for bounce-notification loop prevention: fail() must call
// notifier.RecordFail for an ordinary client message, since that is a real
// bounce worth telling someone about, but must not call it again for a
// notification message's own delivery failure, which is exactly how a
// notification loop would start.
func TestFailRecordsRealClientFailureButNotANotificationsOwn(t *testing.T) {
	m, sp := testManager(t)

	env := spool.Envelope{From: "a@example.at", To: []string{"b@example.net"}, Route: "m365", Client: "printers", Received: time.Now()}
	if _, err := sp.Enqueue(env, strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	meta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("claim failed")
	}
	m.fail(meta, "smarthost rejected it")

	if got := m.Notifier().Pending(); got != 1 {
		t.Fatalf("pending = %d after a real client failure, want 1", got)
	}

	notifEnv := spool.Envelope{From: "", To: []string{"ops@example.at"}, Route: "m365", Client: "printers", Received: time.Now(), Notification: true}
	if _, err := sp.Enqueue(notifEnv, strings.NewReader("y"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	notifMeta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("claim failed")
	}
	m.fail(notifMeta, "notify route unreachable")

	if got := m.Notifier().Pending(); got != 1 {
		t.Fatalf("pending = %d after a notification's own failure, want still 1 (no loop)", got)
	}
}
