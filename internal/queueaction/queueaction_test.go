// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package queueaction

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

func testActor(t *testing.T) (*Actor, *spool.Spool, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	sp, err := spool.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(sp, st, slog.New(slog.NewTextHandler(io.Discard, nil))), sp, st
}

// queued puts one message in the spool and in history, the way the listener
// does when it accepts a submission.
func queued(t *testing.T, sp *spool.Spool, st *store.Store) spool.ID {
	t.Helper()
	now := time.Now().UTC()
	env := spool.Envelope{From: "device@example.at", To: []string{"ops@example.net"},
		Client: "printers", Route: "m365", Listener: "smtp",
		RemoteAddr: "10.10.5.9", Received: now}
	id, err := sp.Enqueue(env, strings.NewReader("Subject: x\r\n\r\nbody\r\n"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordMessage(store.MessageRecord{
		QueueID: id.String(), Client: "printers", Route: "m365",
		EnvelopeFrom: "device@example.at", Recipients: `["ops@example.net"]`,
		Listener: "smtp", RemoteAddr: "10.10.5.9",
		ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// The five outcomes of delete, which the dashboard and the JSON API each used
// to decide for themselves. They are decisions about mail, so a disagreement
// between the two entry points is a disagreement about what happened to a
// message -- which is why they now share this.
func TestDeleteOutcomes(t *testing.T) {
	t.Run("a queued message is discarded", func(t *testing.T) {
		a, sp, st := testActor(t)
		id := queued(t, sp, st)
		if got := a.Delete(id, "dashboard", "127.0.0.1", ""); got != Done {
			t.Fatalf("outcome %v, want Done", got)
		}
		if sp.Has(id) {
			t.Error("the spool copy survived")
		}
		// History is kept by design; only retention ever purges a row.
		if msg, err := st.FindMessageByID(id.String()); err != nil || msg == nil {
			t.Error("the history row was removed, which delete must not do")
		}
	})

	t.Run("no spool copy, history still calls it active", func(t *testing.T) {
		a, sp, st := testActor(t)
		id := queued(t, sp, st)
		// The spool copy vanishes without the history being told: a dropped
		// half-pair at startup, or files removed by hand.
		if err := sp.Discard(id); err != nil {
			t.Fatal(err)
		}
		if got := a.Delete(id, "dashboard", "127.0.0.1", ""); got != Cleared {
			t.Fatalf("outcome %v, want Cleared -- otherwise the entry is listed forever with nothing able to remove it", got)
		}
	})

	t.Run("nothing anywhere", func(t *testing.T) {
		a, _, _ := testActor(t)
		if got := a.Delete(spool.ID("AAAAAAAAAAAAAAAA"), "dashboard", "127.0.0.1", ""); got != Missing {
			t.Fatalf("outcome %v, want Missing", got)
		}
	})

	t.Run("leased by a delivery worker", func(t *testing.T) {
		a, sp, st := testActor(t)
		id := queued(t, sp, st)
		if _, ok := sp.Claim(time.Now()); !ok {
			t.Fatal("nothing to claim")
		}
		if got := a.Delete(id, "dashboard", "127.0.0.1", ""); got != Busy {
			t.Fatalf("outcome %v, want Busy -- acting would race the worker", got)
		}
	})
}

func TestRequeueOutcomes(t *testing.T) {
	t.Run("a message with a spool copy goes back", func(t *testing.T) {
		a, sp, st := testActor(t)
		id := queued(t, sp, st)
		if got := a.Requeue(id, "dashboard", "127.0.0.1", ""); got != Done {
			t.Fatalf("outcome %v, want Done", got)
		}
	})

	t.Run("no spool copy is missing, never cleared", func(t *testing.T) {
		a, sp, st := testActor(t)
		id := queued(t, sp, st)
		if err := sp.Discard(id); err != nil {
			t.Fatal(err)
		}
		// Unlike delete there is nothing to reconcile: without a body there
		// is nothing to send, so reporting anything but Missing would
		// promise a retry that cannot happen.
		if got := a.Requeue(id, "dashboard", "127.0.0.1", ""); got != Missing {
			t.Fatalf("outcome %v, want Missing", got)
		}
	})

	t.Run("leased by a delivery worker", func(t *testing.T) {
		a, sp, st := testActor(t)
		id := queued(t, sp, st)
		if _, ok := sp.Claim(time.Now()); !ok {
			t.Fatal("nothing to claim")
		}
		if got := a.Requeue(id, "dashboard", "127.0.0.1", ""); got != Busy {
			t.Fatalf("outcome %v, want Busy", got)
		}
	})
}

// Every action that changes something is audited, under the name the caller
// gives: "dashboard" for the web UI, the token's name for the JSON API. An
// action that changed nothing is not audited, so the log records what
// happened rather than what was attempted.
func TestAuditRecordsWhoActed(t *testing.T) {
	a, sp, st := testActor(t)
	id := queued(t, sp, st)

	if got := a.Delete(id, "ops-token", "10.0.0.5", "bulk"); got != Done {
		t.Fatalf("outcome %v, want Done", got)
	}
	entries, err := st.FindAuditByQueueID(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("%d audit entries, want 1", len(entries))
	}
	if entries[0].TokenName != "ops-token" {
		t.Errorf("audit records %q as the actor, want ops-token", entries[0].TokenName)
	}
	if entries[0].SourceAddr != "10.0.0.5" {
		t.Errorf("audit records %q as the source, want 10.0.0.5", entries[0].SourceAddr)
	}
	if entries[0].Action != "delete" {
		t.Errorf("audit records action %q, want delete", entries[0].Action)
	}

	// A requeue of something that is not there changed nothing.
	if got := a.Requeue(spool.ID("BBBBBBBBBBBBBBBB"), "ops-token", "10.0.0.5", ""); got != Missing {
		t.Fatal("expected Missing")
	}
	if entries, err := st.FindAuditByQueueID("BBBBBBBBBBBBBBBB"); err != nil || len(entries) != 0 {
		t.Errorf("an action that changed nothing was audited: %d entries", len(entries))
	}
}

// failingJournal is a Journal whose writes fail, which a real SQLite file
// cannot be asked to do on demand. It is what makes the Failed outcome
// reachable: Delete reports it when reconciling a message with no spool copy
// cannot be completed, and the caller turns that into a 500 rather than the
// 404 an unreconciled message would have produced.
type failingJournal struct{ err error }

func (j failingJournal) RecordRemoval(string) error { return j.err }
func (j failingJournal) ReconcileRemoved(string) (bool, error) {
	return false, j.err
}
func (j failingJournal) RecordAudit(_, _, _, _, _ string) error { return j.err }

// emptyQueue holds nothing, so every action against it reports ErrNotFound.
type emptyQueue struct{}

func (emptyQueue) Requeue(spool.ID) error { return spool.ErrNotFound }
func (emptyQueue) Discard(spool.ID) error { return spool.ErrNotFound }

func TestDeleteReportsFailedWhenReconciliationCannotBeWritten(t *testing.T) {
	a := New(emptyQueue{}, failingJournal{err: errors.New("database is locked")},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	id, err := spool.ParseID("AAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Delete(id, "dashboard", "127.0.0.1", ""); got != Failed {
		t.Fatalf("delete outcome = %v, want Failed: a history write that cannot be "+
			"completed must not read as a message that was never there", got)
	}
}
