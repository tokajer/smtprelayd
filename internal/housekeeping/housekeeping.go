// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package housekeeping runs the spool/failed retention sweep, the history
// store's retention sweep and the spool quota warning on their own
// goroutine, apart from the delivery manager's dispatch loop.
package housekeeping

import (
	"context"
	"log/slog"
	"time"

	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// passInterval is how often Housekeeper polls. A retention DELETE (15.6s
// measured at a million rows) or the hourly spool/failed sweep would
// otherwise delay the next dispatch tick, and a dispatch pass over a deep
// queue would otherwise delay both sweeps and the quota warning, which is why
// this runs on its own goroutine rather than sharing delivery's.
const passInterval = 5 * time.Second

// Housekeeper runs the spool/failed retention sweep, the history store's
// retention sweep and the spool quota warning. It uses *store.Store directly
// rather than delivery.Journal, since RetentionSweep is not part of the
// narrower interface the delivery manager itself needs.
type Housekeeper struct {
	spool *spool.Spool
	store *store.Store
	log   *slog.Logger

	// lastFailedSweep and quotaWarned are read and written only from Run's
	// own goroutine.
	lastFailedSweep time.Time
	quotaWarned     bool
}

// New builds a Housekeeper. Logs as component=delivery so existing log
// searches still match: the sweeps it runs are still delivery's concern as
// far as an operator watching the logs is concerned.
func New(sp *spool.Spool, st *store.Store, log *slog.Logger) *Housekeeper {
	return &Housekeeper{spool: sp, store: st, log: log.With("component", "delivery")}
}

// Run does one pass immediately, then one pass per passInterval tick until
// ctx is done.
func (h *Housekeeper) Run(ctx context.Context) {
	h.pass(ctx, time.Now())

	t := time.NewTicker(passInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.pass(ctx, time.Now())
		}
	}
}

// pass runs the failed-spool sweep, the history retention sweep and the
// quota check once.
func (h *Housekeeper) pass(ctx context.Context, now time.Time) {
	h.sweepFailed(now)
	h.sweepHistory(ctx, now)
	h.reportQuota(h.spool.QuotaWarning())
}

// failedSweepInterval throttles the spool/failed retention sweep. Housekeeper
// already runs on its own ticker, but it walks a directory index, and the
// retention it enforces is measured in days, so running it on every tick
// would be pure waste.
const failedSweepInterval = time.Hour

func (h *Housekeeper) sweepFailed(now time.Time) {
	if now.Sub(h.lastFailedSweep) < failedSweepInterval {
		return
	}
	h.lastFailedSweep = now
	if removed, freed := h.spool.SweepFailed(now); removed > 0 {
		h.log.Info("failed spool retention sweep",
			"removed", removed, "freed_bytes", freed)
	}
}

// sweepHistory runs the history store's retention delete here rather than
// inside a journal write. The store keeps its own hourly gate, so calling it
// every tick costs one comparison.
func (h *Housekeeper) sweepHistory(ctx context.Context, now time.Time) {
	if deleted := h.store.RetentionSweep(ctx, now); deleted > 0 {
		h.log.Info("history retention sweep", "deleted_rows", deleted)
	}
}

// reportQuota logs the spool quota warning only on a transition. Housekeeper
// polls every passInterval (5s), so logging the current state on each poll
// rather than the edge would bury the one line an operator needs to notice
// under constant repetition.
func (h *Housekeeper) reportQuota(used, quota int64, over bool) {
	switch {
	case over && !h.quotaWarned:
		var percent int64
		if quota > 0 {
			percent = used * 100 / quota
		}
		h.log.Warn("spool is filling up",
			"used_bytes", used, "max_bytes", quota, "percent", percent)
	case !over && h.quotaWarned:
		h.log.Info("spool is back below the quota warning threshold",
			"used_bytes", used, "max_bytes", quota)
	}
	h.quotaWarned = over
}
