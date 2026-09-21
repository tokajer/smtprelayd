// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package bounce

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/selfmail"
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
	cfg    *config.Config
	spool  *spool.Spool
	store  *store.Store
	mailer *selfmail.Mailer
	log    *slog.Logger

	mu      sync.Mutex
	pending map[string][]string // client name -> queue IDs awaiting the next digest
	// overflow counts the failures past maxPendingPerClient, whose IDs are
	// not kept. The digest reports them as a number so its total still
	// matches what actually failed.
	overflow     map[string]int
	hourStart    time.Time
	sentThisHour int
}

// New builds a notifier. It does nothing until Run is started; RecordFail
// may be called beforehand; it will only queue events, never send anything.
func New(cfg *config.Config, sp *spool.Spool, st *store.Store, log *slog.Logger) *Notifier {
	return &Notifier{
		cfg: cfg, spool: sp, store: st, mailer: selfmail.New(sp, st, log.With("component", "bounce")),
		log:     log.With("component", "bounce"),
		pending: map[string][]string{}, overflow: map[string]int{}, hourStart: time.Now(),
	}
}

// maxPendingPerClient bounds how many queue IDs one client accumulates for
// its next digest. The digest itself lists at most maxDigestEntries and says
// how many more there were, and every failure is a history row either way,
// so the IDs past this point buy nothing -- while bounce.max_per_hour can
// suppress sending for an hour at a time, during which nothing drains this.
// The overflow is counted instead of kept, so the digest's total is still
// the true one.
const maxPendingPerClient = 10 * maxDigestEntries

// RecordFail queues a permanently failed or expired message for the next
// digest. Callers must only invoke this when a message has actually been
// moved to spool/failed — a merely deferred message has not failed yet, and
// must not be recorded as a bounce.
func (n *Notifier) RecordFail(client, queueID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.pending[client]) >= maxPendingPerClient {
		n.overflow[client]++
		return
	}
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
	for _, n := range n.overflow {
		total += n
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
	overflow := n.overflow
	n.pending = map[string][]string{}
	n.overflow = map[string]int{}
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
			n.overflow[client] += overflow[client]
		} else {
			n.sentThisHour++
		}
		n.mu.Unlock()

		if capped {
			n.log.Warn("bounce notification suppressed: hourly volume cap reached",
				"client", client, "queued_failures", len(ids)+overflow[client])
			continue
		}

		if err := n.send(client, recipients, ids, overflow[client], now); err != nil {
			n.log.Error("sending bounce digest failed", "client", client, "error", err)
		}
	}
}

// maxDigestEntries bounds how many failures one digest lists in full.
//
// bounce.max_per_hour caps how many digests go out, never how long one is,
// and the length is set by how much mail the clients sent during the outage:
// measured at roughly 167 bytes per entry, 10 000 failures produce a 1.59 MB
// message and 10 000 history lookups. That is unreadable, it is the kind of
// size a smarthost refuses, and it arrives precisely when the operator most
// needs to hear something -- so the notification would fail at the one moment
// it exists for.
//
// Nothing is lost by cutting it off: every failure is already a row in the
// history store, which the closing line points at. 200 is generous for
// reading and small enough that the worst case stays a normal mail.
const maxDigestEntries = 200

// send composes and enqueues one digest for client, listing at most maxDigestEntries of
// them. It is enqueued exactly like any other message — through the spool,
// for the configured notify route — except for the three loop-prevention
// properties that matter here: an empty envelope sender (net/smtp renders
// Mail("") as "MAIL FROM:<>", the standard null reverse path), the
// Notification flag (so the delivery manager never treats its own failure
// as another bounce to notify about), and never having passed through the
// listener at all, which is what keeps it out of sender rewriting.
func (n *Notifier) send(client string, recipients, ids []string, overflow int, now time.Time) error {
	total := len(ids) + overflow
	subject := fmt.Sprintf("[smtprelayd] %d delivery failure(s) for %s", total, client)

	var body strings.Builder
	fmt.Fprintf(&body, "%d message(s) from client %q could not be delivered:\r\n", total, client)

	listed := ids
	if len(listed) > maxDigestEntries {
		listed = listed[:maxDigestEntries]
	}

	for _, id := range listed {
		msg, err := n.store.FindMessageByID(id)
		if err != nil || msg == nil {
			fmt.Fprintf(&body, "\r\nQueue ID:   %s\r\n(history record unavailable)\r\n", id)
			continue
		}
		// msg.Subject is already redacted when history.retain_subjects is
		// off: the store applies that on the way out of every read, which is
		// where it was consolidated to precisely so that no caller has to
		// remember. Re-applying it here was a fourth copy of the policy that
		// happened to agree.
		var code int
		var resp string
		if len(msg.Attempts) > 0 {
			last := msg.Attempts[len(msg.Attempts)-1]
			code, resp = last.SMTPCode, last.SMTPResp
		}
		fmt.Fprintf(&body, "\r\nQueue ID:   %s\r\nFrom:       %s\r\nTo:         %s\r\nSubject:    %s\r\nResponse:   %d %s\r\n",
			id, msg.EnvelopeFrom, strings.Join(msg.Recipients, ", "), msg.Subject, code, resp)
	}

	if omitted := total - len(listed); omitted > 0 {
		fmt.Fprintf(&body, "\r\n... and %d more, not listed here. All %d are in the history:\r\n"+
			"the bounces view, filtered by client %q.\r\n", omitted, total, client)
	}

	queueID, err := n.enqueue(client, recipients, subject, body.String(), now)
	if err != nil {
		return err
	}
	n.log.Info("bounce digest queued", "client", client, "queue_id", queueID,
		"failures", total, "listed", len(listed))
	return nil
}

// Notify enqueues one operator notification through this same channel: the
// configured bounce.sender, the bounce.notify recipients and the
// bounce.notify_route, carrying the loop-prevention properties a digest has.
// It exists so that anything with something to tell the operator reuses the
// contact details and the delivery path already configured for bounces,
// rather than growing a second notion of "who to mail".
//
// source names what produced the notification. It is what recipientsFor
// looks up, so a source sharing a client's name would reach that client's
// bounce.notify override -- callers pass something that cannot collide.
//
// Unlike a digest this is not subject to bounce.max_per_hour. That cap
// exists so a delivery-failure storm cannot become a mail storm; a caller
// here is expected to rate-limit itself to the occasional message, and
// dropping a warning about something expiring would defeat the point of
// sending it.
//
// Returns nil without sending when no recipient is configured at all, which
// is how notifications are switched off.
func (n *Notifier) Notify(source, subject, bodyText string, now time.Time) error {
	recipients := n.recipientsFor(source)
	if len(recipients) == 0 {
		return nil
	}
	queueID, err := n.enqueue(source, recipients, subject, bodyText, now)
	if err != nil {
		return err
	}
	n.log.Info("operator notification queued", "source", source, "queue_id", queueID, "subject", subject)
	return nil
}

// enqueue hands the message to internal/selfmail, which every
// relay-composed message goes through so that the header block and the
// journal record cannot drift apart between the digest, the expiry warning
// and the canary.
//
// The empty envelope sender is what makes this a notification rather than
// ordinary mail: net/smtp renders Mail("") as "MAIL FROM:<>", the standard
// null reverse path, and Notification keeps the delivery manager from
// treating a failure to deliver it as another bounce to report.
func (n *Notifier) enqueue(source string, recipients []string, subject, bodyText string, now time.Time) (string, error) {
	id, err := n.mailer.Send(selfmail.Message{
		HeaderFrom:   n.cfg.Bounce.Sender,
		EnvelopeFrom: "",
		To:           recipients,
		Subject:      subject,
		Body:         bodyText,
		Client:       source,
		Route:        n.cfg.Bounce.NotifyRoute,
		Listener:     "bounce-notifier",
		Kind:         spool.KindNotification,
	}, time.Duration(n.cfg.Queue.MaxLifetimeHours)*time.Hour, now)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
