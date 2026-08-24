// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package canary

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/rewrite"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// clientName is the Envelope.Client value the canary enqueues under. It is
// deliberately unlikely to collide with a real configured client name, so a
// canary failure falls through to the global bounce.notify list rather than
// a real client's own override (see internal/bounce's recipientsFor).
const clientName = "smtprelayd-canary"

// contentType is written into both the message header and its journal
// record, so the two cannot disagree about what was sent.
const contentType = "text/plain; charset=utf-8"

// Runner enqueues one canary message every [canary].interval_minutes.
// Delivery, retry and permanent-failure handling are deliberately not this
// package's concern: the message is enqueued exactly like any other and
// left for the already-running delivery.Manager to carry, so a stuck route
// delays or fails the canary exactly as it would any real message, and a
// permanent failure is picked up by the bounce notifier's existing
// RecordFail path without this package needing to know that happened.
type Runner struct {
	cfg   *config.Config
	spool *spool.Spool
	store *store.Store
	log   *slog.Logger
}

// New builds a runner. It does nothing until Run is started.
func New(cfg *config.Config, sp *spool.Spool, st *store.Store, log *slog.Logger) *Runner {
	return &Runner{cfg: cfg, spool: sp, store: st, log: log.With("component", "canary")}
}

// Run enqueues a canary message every [canary].interval_minutes until ctx is
// cancelled. It returns immediately if the canary is not configured at all,
// since a zero or negative interval would otherwise spin.
func (r *Runner) Run(ctx context.Context) {
	if r.cfg.Canary.Recipient == "" {
		return
	}
	interval := time.Duration(r.cfg.Canary.IntervalMinutes) * time.Minute
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.send(time.Now()); err != nil {
				r.log.Error("sending canary message failed", "error", err)
			}
		}
	}
}

// send composes and enqueues one canary message. Unlike a bounce digest it
// is a perfectly ordinary message: Notification stays false, so a permanent
// failure reaches bounce.Notifier.RecordFail through delivery.Manager.fail
// exactly as any real message's would, reusing that existing alerting path
// rather than building a second one.
func (r *Runner) send(now time.Time) error {
	subject := fmt.Sprintf("[smtprelayd] canary %s", now.Format("2006-01-02 15:04:05 MST"))

	var body strings.Builder
	fmt.Fprintf(&body, "From: %s\r\n", r.cfg.Canary.Sender)
	fmt.Fprintf(&body, "To: %s\r\n", r.cfg.Canary.Recipient)
	fmt.Fprintf(&body, "Subject: %s\r\n", subject)
	fmt.Fprintf(&body, "Date: %s\r\n", now.Format(time.RFC1123Z))
	body.WriteString("Content-Type: " + contentType + "\r\n\r\n")
	fmt.Fprintf(&body, "This is an automated canary message from smtprelayd on %s, sent through route %q.\r\n",
		r.cfg.Service.Hostname, r.cfg.Canary.Route)
	body.WriteString("If it stops arriving on schedule, delivery through that route may be failing silently.\r\n")

	env := spool.Envelope{
		From:       r.cfg.Canary.Sender,
		To:         []string{r.cfg.Canary.Recipient},
		Client:     clientName,
		Route:      r.cfg.Canary.Route,
		Listener:   "canary",
		RemoteAddr: "internal",
		Received:   now,
		Canary:     true,
	}
	lifetime := time.Duration(r.cfg.Queue.MaxLifetimeHours) * time.Hour
	data := body.String()
	queueID, err := r.spool.Enqueue(env, strings.NewReader(data), 0, lifetime)
	if err != nil {
		return fmt.Errorf("canary: enqueue: %w", err)
	}

	recipientsJSON, _ := json.Marshal(env.To)
	if rerr := r.store.RecordMessage(store.MessageRecord{
		QueueID:      queueID.String(),
		Client:       clientName,
		Route:        r.cfg.Canary.Route,
		EnvelopeFrom: r.cfg.Canary.Sender,
		Recipients:   string(recipientsJSON),
		Subject:      subject,
		Listener:     "canary",
		RemoteAddr:   "internal",
		ContentType:  contentType,
		SizeBytes:    int64(len(data)),
		HeaderCount:  rewrite.HeaderCount(headerBlock(data)),
		ReceivedAt:   now,
		ExpiresAt:    now.Add(lifetime),
	}); rerr != nil {
		r.log.Warn("recording canary in history failed", "queue_id", queueID.String(), "error", rerr)
	}

	r.log.Info("canary message queued", "queue_id", queueID.String(), "route", r.cfg.Canary.Route)
	return nil
}

// headerBlock returns the header part of a composed message, terminating
// blank line included. A message with no blank line at all is all headers.
func headerBlock(data string) string {
	if i := strings.Index(data, "\r\n\r\n"); i >= 0 {
		return data[:i+4]
	}
	return data
}
