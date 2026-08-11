// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package bounce

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// Notifier batches permanently failed or expired messages into periodic
// digest notification mail. It is deliberately decoupled from the delivery
// path it reports on: RecordFail only ever adds a queue ID to an in-memory
// bucket, and the digest itself is composed and enqueued later, on Run's own
// schedule, from what the store already recorded — never from data carried
// through the failure callback itself.
type Notifier struct {
	cfg   *config.Config
	spool *spool.Spool
	store *store.Store
	log   *slog.Logger

	mu           sync.Mutex
	pending      map[string][]string // client name -> queue IDs awaiting the next digest
	hourStart    time.Time
	sentThisHour int
}

// New builds a notifier. It does nothing until Run is started; RecordFail
// may be called beforehand; it will only queue events, never send anything.
func New(cfg *config.Config, sp *spool.Spool, st *store.Store, log *slog.Logger) *Notifier {
	return &Notifier{
		cfg: cfg, spool: sp, store: st, log: log.With("component", "bounce"),
		pending: map[string][]string{}, hourStart: time.Now(),
	}
}

// RecordFail queues a permanently failed or expired message for the next
// digest. Callers must only invoke this when a message has actually been
// moved to spool/failed — a merely deferred message has not failed yet, and
// must not be recorded as a bounce.
func (n *Notifier) RecordFail(client, queueID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.pending[client] = append(n.pending[client], queueID)
}

// Pending reports how many failures are currently queued for the next
// digest, across every client. Exposed for tests that check RecordFail was
// (or, for a notification's own failure, was not) called, without reaching
// into unexported state.
func (n *Notifier) Pending() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	total := 0
	for _, ids := range n.pending {
		total += len(ids)
	}
	return total
}

// Run dispatches digests every [bounce].digest_minutes until ctx is
// cancelled. It returns immediately if notifications are not configured at
// all, since a zero or negative interval would otherwise spin.
func (n *Notifier) Run(ctx context.Context) {
	interval := time.Duration(n.cfg.Bounce.DigestMinutes) * time.Minute
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
			n.dispatch(time.Now())
		}
	}
}

// recipientsFor resolves the notification recipients for a client: its own
// bounce.notify override if it set one, otherwise the global bounce.notify
// list. Config validation guarantees no client sets any other bounce.* field,
// so this is the only override that can apply.
func (n *Notifier) recipientsFor(client string) []string {
	for _, cl := range n.cfg.Clients {
		if cl.Name == client && len(cl.Bounce.Notify) > 0 {
			return cl.Bounce.Notify
		}
	}
	return n.cfg.Bounce.Notify
}

// dispatch drains the pending digests and sends one message per client that
// has failures to report, sharing the hourly volume cap across all of them.
func (n *Notifier) dispatch(now time.Time) {
	n.mu.Lock()
	if now.Sub(n.hourStart) >= time.Hour {
		n.hourStart, n.sentThisHour = now, 0
	}
	pending := n.pending
	n.pending = map[string][]string{}
	n.mu.Unlock()

	for client, ids := range pending {
		recipients := n.recipientsFor(client)
		if len(recipients) == 0 {
			// Notifications are effectively disabled for this client: no
			// global list and no override. The failures are not retried
			// into a future digest, since there will never be anyone to
			// send it to.
			continue
		}

		n.mu.Lock()
		capped := n.sentThisHour >= n.cfg.Bounce.MaxPerHour
		if capped {
			// Recorded for the next hour rather than dropped, per the
			// volume cap's design: exceeding it suppresses sending, not
			// the underlying record of what failed.
			n.pending[client] = append(n.pending[client], ids...)
		} else {
			n.sentThisHour++
		}
		n.mu.Unlock()

		if capped {
			n.log.Warn("bounce notification suppressed: hourly volume cap reached",
				"client", client, "queued_failures", len(ids))
			continue
		}

		if err := n.send(client, recipients, ids, now); err != nil {
			n.log.Error("sending bounce digest failed", "client", client, "error", err)
		}
	}
}

// send composes and enqueues one digest for client, listing every message in
// ids. It is enqueued exactly like any other message — through the spool,
// for the configured notify route — except for the three loop-prevention
// properties that matter here: an empty envelope sender (net/smtp renders
// Mail("") as "MAIL FROM:<>", the standard null reverse path), the
// Notification flag (so the delivery manager never treats its own failure
// as another bounce to notify about), and never having passed through the
// listener at all, which is what keeps it out of sender rewriting.
func (n *Notifier) send(client string, recipients, ids []string, now time.Time) error {
	subject := fmt.Sprintf("[smtprelayd] %d delivery failure(s) for %s", len(ids), client)

	var body strings.Builder
	fmt.Fprintf(&body, "From: %s\r\n", n.cfg.Bounce.Sender)
	fmt.Fprintf(&body, "To: %s\r\n", strings.Join(recipients, ", "))
	fmt.Fprintf(&body, "Subject: %s\r\n", subject)
	fmt.Fprintf(&body, "Date: %s\r\n", now.Format(time.RFC1123Z))
	body.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	fmt.Fprintf(&body, "%d message(s) from client %q could not be delivered:\r\n", len(ids), client)

	for _, id := range ids {
		msg, err := n.store.FindMessageByID(id)
		if err != nil || msg == nil {
			fmt.Fprintf(&body, "\r\nQueue ID:   %s\r\n(history record unavailable)\r\n", id)
			continue
		}
		subj := msg.Subject
		if !n.cfg.History.RetainSubjects {
			subj = "[redacted]"
		}
		var code int
		var resp string
		if len(msg.Attempts) > 0 {
			last := msg.Attempts[len(msg.Attempts)-1]
			code, resp = last.SMTPCode, last.SMTPResp
		}
		fmt.Fprintf(&body, "\r\nQueue ID:   %s\r\nFrom:       %s\r\nTo:         %s\r\nSubject:    %s\r\nResponse:   %d %s\r\n",
			id, msg.EnvelopeFrom, strings.Join(msg.Recipients, ", "), subj, code, resp)
	}

	env := spool.Envelope{
		From:         "",
		To:           recipients,
		Client:       client,
		Route:        n.cfg.Bounce.NotifyRoute,
		Listener:     "bounce-notifier",
		RemoteAddr:   "internal",
		Received:     now,
		Notification: true,
	}
	lifetime := time.Duration(n.cfg.Queue.MaxLifetimeHours) * time.Hour
	queueID, err := n.spool.Enqueue(env, strings.NewReader(body.String()), 0, lifetime)
	if err != nil {
		return fmt.Errorf("bounce: enqueue digest: %w", err)
	}

	recipientsJSON, _ := json.Marshal(recipients)
	if rerr := n.store.RecordMessage(queueID.String(), client, n.cfg.Bounce.NotifyRoute, "", "",
		string(recipientsJSON), subject, "bounce-notifier", "internal", now, now.Add(lifetime), false); rerr != nil {
		n.log.Warn("recording digest in history failed", "queue_id", queueID.String(), "error", rerr)
	}

	n.log.Info("bounce digest queued", "client", client, "queue_id", queueID.String(), "failures", len(ids))
	return nil
}
