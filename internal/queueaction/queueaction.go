// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package queueaction carries out the operator's two state-changing actions
// on a queued message: put it back for immediate retry, or remove it.
//
// It exists because both entry points -- the dashboard and the JSON API --
// used to decide this themselves, five branches each, written out twice. The
// JSON API's own comment asked for what nothing enforced: "the dashboard's
// delete does the same; the two entry points must not disagree about what
// delete means." They are decisions about mail, not about presentation, so
// they belong below the transport rather than once per transport. What each
// caller still owns is how an Outcome is rendered -- a status code, or a
// tally in a bulk banner.
package queueaction

import (
	"errors"
	"log/slog"

	"github.com/tokajer/smtprelayd/internal/spool"
)

// Outcome is what an action did to one message.
type Outcome int

const (
	// Done: the spool copy was requeued or discarded.
	Done Outcome = iota
	// Cleared: delete only. There was no spool copy left, and the history
	// row that still called the message active was reconciled.
	Cleared
	// Busy: a delivery worker holds the lease. Acting would race it.
	Busy
	// Missing: nothing to act on, in the spool or in history.
	Missing
	// Failed: the reason is logged; the caller reports a failure.
	Failed
)

// Queue is what this package needs from the spool: the two operations that
// change a message's fate, and nothing else. Declared here, on the consumer
// side, the way internal/delivery declares FailRecorder and internal/metrics
// declares TokenAger -- *spool.Spool satisfies it without knowing this
// exists.
type Queue interface {
	Requeue(id spool.ID) error
	Discard(id spool.ID) error
}

// Journal is what this package needs from the history store: the three
// writes that record what an action did. Declared here for the reason Queue
// is, and with a second one: the Failed outcome is reached only when one of
// these fails, which against a real SQLite file is not a state a test can ask
// for.
type Journal interface {
	RecordRemoval(queueID string) error
	ReconcileRemoved(queueID string) (bool, error)
	RecordAudit(tokenName, sourceAddr, action, queueID, details string) error
}

// Actor performs the actions and writes the audit row that records them.
type Actor struct {
	spool Queue
	store Journal
	log   *slog.Logger
}

func New(q Queue, j Journal, log *slog.Logger) *Actor {
	return &Actor{spool: q, store: j, log: log}
}

// Requeue moves one message back into the live queue for immediate retry.
//
// A message whose spool copy is gone cannot be requeued -- there is no body
// to send -- so unlike Delete this has nothing to reconcile and reports it as
// Missing.
//
// by names who acted ("dashboard", or an API token's name) and source is the
// address they acted from; both go into the audit row.
func (a *Actor) Requeue(id spool.ID, by, source, details string) Outcome {
	switch err := a.spool.Requeue(id); {
	case err == nil:
		a.audit(by, source, "requeue", id, details)
		return Done
	case errors.Is(err, spool.ErrNotFound):
		return Missing
	case errors.Is(err, spool.ErrBusy):
		return Busy
	default:
		a.log.Error("requeue failed", "queue_id", id.String(), "error", err)
		return Failed
	}
}

// Delete removes one message from the spool, wherever it currently sits,
// while retaining its history row: the admin delete action keeps history by
// design, and only the store's retention job ever purges a row.
//
// The ErrNotFound branch is the one that matters. A message can be listed by
// the queue view with no spool copy behind it -- a startup recovery dropped a
// half-written pair, an operator removed the files by hand, a crash landed
// between the unlink and the attempt row. Answering "not found" there left
// the entry in every listing with nothing able to clear it, which is the
// opposite of what delete is for.
//
// This cannot mislabel a message that was in fact delivered: the delivery
// worker records the "delivered" attempt before it unlinks the body, and a
// leased message answers Busy rather than reaching this branch, so the only
// way in is a message with no lease, no files and a history row that still
// calls it active. ReconcileRemoved re-checks that last part itself and
// writes nothing otherwise.
func (a *Actor) Delete(id spool.ID, by, source, details string) Outcome {
	switch err := a.spool.Discard(id); {
	case err == nil:
		if rerr := a.store.RecordRemoval(id.String()); rerr != nil {
			a.log.Warn("removal record write failed", "queue_id", id.String(), "error", rerr)
		}
		a.audit(by, source, "delete", id, details)
		return Done
	case errors.Is(err, spool.ErrNotFound):
		cleared, rerr := a.store.ReconcileRemoved(id.String())
		if rerr != nil {
			a.log.Error("reconciling a message with no spool copy failed",
				"queue_id", id.String(), "error", rerr)
			return Failed
		}
		if !cleared {
			return Missing
		}
		a.log.Info("queue entry cleared for a message with no spool copy",
			"queue_id", id.String(), "source", source)
		a.audit(by, source, "delete", id, joinDetails(details, "no spool copy: history reconciled"))
		return Cleared
	case errors.Is(err, spool.ErrBusy):
		return Busy
	default:
		a.log.Error("delete failed", "queue_id", id.String(), "error", err)
		return Failed
	}
}

// audit records an operator action. A failure to write it is logged and not
// returned: the action itself already happened, and reporting it as failed
// would invite the operator to repeat something irreversible.
func (a *Actor) audit(by, source, action string, id spool.ID, details string) {
	if err := a.store.RecordAudit(by, source, action, id.String(), details); err != nil {
		a.log.Warn("audit log write failed", "action", action, "queue_id", id.String(), "error", err)
	}
}

// joinDetails combines a caller's own note with one this package adds.
func joinDetails(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}
