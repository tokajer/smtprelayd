// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package delivery runs the delivery workers and retry scheduling.
package delivery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/delivery/smarthost"
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/queueid"
	"github.com/tokajer/smtprelayd/internal/ratelimit"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// pollInterval bounds how long a message waits for the next dispatch pass
// when nothing wakes one sooner. Spool.Wake covers a freshly committed
// message, not one that becomes due on its own later -- an operator's
// requeue, or a held/deferred message whose backoff has elapsed -- so the
// ticker is what notices those, and what recovers dispatch after a restart.
const pollInterval = 5 * time.Second

// wakeDebounce coalesces a burst of Wake signals into one dispatch pass: a
// listener accepting many messages back to back would otherwise cost one
// full index scan under the spool mutex per message committed.
const wakeDebounce = 100 * time.Millisecond

// Journal is what this package needs from the history store to record one
// delivery attempt. Declared here, on the consumer side, the way
// queueaction.Journal is: it lets the journal-failure path be tested with a
// fake that returns an error, which a real *store.Store backed by SQLite is
// not a state a test can put on demand.
type Journal interface {
	RecordAttempt(queueID queueid.ID, attemptNum int, smtpCode int, smtpResponse string, class store.Class, nextAttemptAt *time.Time) error
}

// FailRecorder is told about every message that failed permanently or
// expired, once it has been moved to spool/failed. It is the whole of what
// this package needs from the bounce notifier: declaring it here, on the
// consumer side, keeps internal/bounce -- and behind it selfmail and the
// message composition path -- out of the delivery manager's imports for the
// sake of one callback.
type FailRecorder interface {
	RecordFail(origin string, id queueid.ID)
}

// Manager drains the spool into the configured routes.
type Manager struct {
	cfg     *config.Config
	spool   *spool.Spool
	history Journal
	log     *slog.Logger
	metrics *metrics.Registry
	fails   FailRecorder

	// routes holds the per-route concurrency budget, limits the per-route
	// messages per minute, tokens the OAuth2 source for xoauth2 routes.
	//
	// rate paces what one smarthost is handed: Microsoft 365 answers a burst
	// with 4.7.500 rather than queueing it, and a rejected attempt costs a
	// full connection and an authentication round trip, so pacing here is
	// cheaper than retrying there. It is internal/ratelimit, the same bucket
	// the listener caps a client with.
	routes map[string]chan struct{}
	limits map[string]int
	tokens map[string]smarthost.TokenSource
	rate   *ratelimit.Limiter
	wg     sync.WaitGroup

	// now is where every scheduling decision in this file reads the current
	// time from: ClaimBatch, the rate limiter, the expiry check and the
	// backoff/hold deadlines. Defaults to time.Now; only a test assigns it,
	// which is what lets a temporary failure past a message's expiry be
	// driven deterministically instead of by a real clock.
	now func() time.Time
}

// New builds the delivery manager. Each route gets its own concurrency budget
// so that one slow smarthost cannot starve the others.
//
// reg, tokens and fails are injected rather than built here: the registry is
// shared with the listener, the dashboard and the metrics endpoint, the
// OAuth2 token sources are built once in the composition root and registered
// with reg there (see cmd/smtprelayd's buildTokenSources), and the notifier
// runs on its own goroutine that the caller owns -- so none of the three is
// this package's to construct. fails may be nil, in which case permanent
// failures are moved aside without anyone being told.
func New(cfg *config.Config, sp *spool.Spool, j Journal, reg *metrics.Registry, tokens map[string]smarthost.TokenSource, fails FailRecorder, log *slog.Logger) *Manager {
	m := &Manager{
		cfg: cfg, spool: sp, history: j, log: log.With("component", "delivery"),
		metrics: reg, fails: fails,
		routes: map[string]chan struct{}{},
		limits: map[string]int{},
		tokens: tokens,
		rate:   ratelimit.New(),
		now:    time.Now,
	}
	for _, r := range cfg.Routes {
		m.routes[r.Name] = make(chan struct{}, r.MaxConcurrent)
		m.limits[r.Name] = r.RateLimitPerMin
	}
	return m
}

// VerifyTokens eagerly acquires a token for every xoauth2 route. Without this,
// authms365.TokenSource fetches nothing until the first message is attempted,
// so a rejected credential or an unreachable tenant is invisible at startup
// and only surfaces once mail is already queued behind it.
//
// What the caller does with the error depends on its type. An
// authms365.CredentialError is the endpoint refusing these credentials, which
// no retry changes, and serve() aborts startup on it (decided 2026-08-21,
// narrowed 2026-09-18). Any other error is the endpoint being unreachable --
// a timeout, a 5xx, a refused connection -- and the caller logs it and
// starts anyway: the listeners must bind so that devices can hand their mail
// over, and the token source retries at the first delivery attempt. Routes
// iterate in configuration order for a deterministic error when more than
// one is broken; a route with no cached source (auth other than xoauth2) is
// skipped, since there is nothing to verify over the network for a static
// credential.
func (m *Manager) VerifyTokens(ctx context.Context) error {
	for _, r := range m.cfg.Routes {
		ts, ok := m.tokens[r.Name]
		if !ok {
			continue
		}
		if _, err := ts.Token(ctx); err != nil {
			return fmt.Errorf("route %s: %w", r.Name, err)
		}
	}
	return nil
}

// claimBatchSize is how many due messages one scan of the spool index
// returns. Large enough that a drain costs few scans, small enough that a
// tick's first batch starts being delivered promptly rather than after the
// whole queue has been leased.
const claimBatchSize = 1000

// Run dispatches queued messages until ctx is cancelled, then waits for the
// attempts already in flight.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(pollInterval)
	defer t.Stop()

	for {
		if !m.dispatch(ctx) {
			m.wg.Wait()
			return
		}

		select {
		case <-ctx.Done():
			m.wg.Wait()
			return
		case <-t.C:
		case <-m.spool.Wake():
			// A burst of commits wakes this once each; waiting wakeDebounce
			// out before dispatching coalesces them into one pass instead of
			// one full index scan per message.
			select {
			case <-time.After(wakeDebounce):
			case <-ctx.Done():
				m.wg.Wait()
				return
			}
		}
	}
}

// dispatch drains everything due into workers, in batches, and reports
// whether the loop should continue. A false return means ctx was cancelled.
//
// A route that has no worker slot free, or that the rate limiter is pacing,
// is recorded in saturated and excluded from every later scan in this tick.
// Without that the scan kept re-finding the messages queued behind a hanging
// smarthost -- one whole scan of the index per message, only to hold it
// again -- which is what made a deep queue quadratic.
func (m *Manager) dispatch(ctx context.Context) bool {
	saturated := map[string]bool{}
	skip := func(route string) bool { return saturated[route] }

	for {
		batch := m.spool.ClaimBatch(m.now(), claimBatchSize, skip)
		for i, meta := range batch {
			if !m.dispatchOne(ctx, meta, saturated) {
				// Cancelled: every message still in this batch is leased and
				// has to go back, or it stays in flight until the restart.
				m.releaseFrom(batch, i)
				return false
			}
		}
		if len(batch) < claimBatchSize {
			// A short batch means the index had nothing left to give, so
			// scanning again to confirm that would cost a second pass under
			// the spool mutex for nothing: anything committed since this scan
			// started left its own pending Wake, and that message was
			// indexed before the send, so the pass it wakes will see it.
			return true
		}
	}
}

// releaseFrom returns the messages of a cancelled batch from index first
// onwards, which dispatchOne released nothing for.
//
// The index rather than the message: dispatch knows where it stopped, and
// re-finding that position by comparing pointers made the correctness of this
// depend on ClaimBatch handing out distinct copies -- true today, stated
// nowhere, and wrong by one suffix if it ever stops being true.
//
// Defer, not Release: a cancelled dispatch changed nothing about these
// messages, so putting them back needs no metadata write or fsync, only
// clearing the lease.
func (m *Manager) releaseFrom(batch []*spool.Meta, first int) {
	for _, meta := range batch[first:] {
		m.spool.Defer(meta, meta.NextAttempt)
	}
}

// dispatchOne hands one claimed message to a worker, or puts it back when it
// cannot be delivered now. It reports false only when ctx was cancelled, in
// which case the caller releases this message and the rest of its batch.
func (m *Manager) dispatchOne(ctx context.Context, meta *spool.Meta, saturated map[string]bool) bool {
	if ctx.Err() != nil {
		// A message that was only just held or deferred (now due again on
		// the next scan) must go back rather than be re-claimed and attempted
		// during shutdown; the caller releases it exactly as it does for a
		// cancellation found later in this batch.
		return false
	}
	route := meta.Envelope.Route
	budget, ok := m.routes[route]
	if !ok {
		log := m.log.With("queue_id", meta.ID.String(), "route", route)
		log.Error("queued message references unknown route")
		m.failUnsendable(log, meta, "route no longer configured")
		return true
	}
	// Slot first, rate limit second; see the note at the Allow call below for
	// why the order matters.
	select {
	case budget <- struct{}{}:
	case <-ctx.Done():
		return false
	default:
		// Never block for a slot. ClaimBatch returns the globally oldest due
		// messages whatever route they belong to, and this is the only
		// dispatcher, so waiting here holds up every other route behind one
		// saturated smarthost -- for as long as an attempt can last, which
		// is limits.delivery_timeout_sec. Measured before this existed: a
		// healthy route's message went out in 100ms next to a working
		// neighbour and was still queued after 8s next to a hanging one.
		//
		// Deferring by pollInterval puts the message back where the next
		// tick finds it, and hold leaves its attempt counter and expiry
		// alone -- it was never offered to the smarthost.
		saturated[route] = true
		m.hold(meta, pollInterval)
		return true
	}
	// Asked only once a slot is actually held: a token consumed without a
	// send lowers the effective rate below the configured one on a
	// saturated route, and the limiter has no way to refund it, so a token
	// spent before the slot check was won would be one send permanently
	// lost from the budget every time no slot was free.
	if wait, ok := m.rate.Allow(route, m.limits[route], m.now()); !ok {
		<-budget
		saturated[route] = true
		m.hold(meta, wait)
		return true
	}
	m.wg.Add(1)
	go func() {
		defer func() {
			<-budget
			m.wg.Done()
		}()
		m.attempt(ctx, meta)
	}()
	return true
}

// attempt makes one delivery attempt and records what it ended in. The two
// halves are apart deliberately: send decides what happened on the wire,
// record decides what that means for the message, the counters and the
// journal, and neither needs to be read to follow the other.
func (m *Manager) attempt(ctx context.Context, meta *spool.Meta) {
	log := m.log.With("queue_id", meta.ID.String(), "route", meta.Envelope.Route)

	route, ok := m.cfg.Route(meta.Envelope.Route)
	if !ok {
		m.failUnsendable(log, meta, "route no longer configured")
		return
	}
	res, ok := m.send(ctx, log, route, meta)
	if !ok {
		return
	}
	if res.err != nil && ctx.Err() != nil {
		// Cancellation expires the smarthost connection, which would
		// otherwise be recorded as a temporary failure and burn a retry step
		// on every restart.
		m.hold(meta, 0)
		return
	}
	meta.Attempts++
	m.record(log, meta, res)
}

// attemptResult is what one trip to the smarthost produced.
type attemptResult struct {
	// err is nil for a delivery that must not be retried, which includes
	// the two partial successes send resolves below.
	err     error
	elapsed time.Duration

	// partialCode and partialResponse carry the refused recipients into the
	// history row, so the addresses survive in the message's attempt detail
	// rather than only in the log: that page is where an operator looks
	// after somebody reports a mail that did not arrive.
	partialCode     int
	partialResponse string
}

// send offers the message to the smarthost and resolves the outcomes that
// mean "delivered, do not retry" into a nil error. It reports false when the
// message could not be offered at all, in which case it has already been
// failed and there is nothing for the caller to record.
func (m *Manager) send(ctx context.Context, log *slog.Logger, route config.Route, meta *spool.Meta) (attemptResult, bool) {
	f, err := m.spool.OpenBody(meta.ID)
	if err != nil {
		log.Error("cannot open queued message", "error", err)
		m.failUnsendable(log, meta, "message body unreadable")
		return attemptResult{}, false
	}
	// The handle is closed explicitly once the body has been sent, before
	// Remove() unlinks it: Windows refuses to delete a file the process
	// itself still holds open, which left delivered bodies behind. The defer
	// only covers the paths that return before that point.
	closed := false
	closeBody := func() {
		if closed {
			return
		}
		closed = true
		if cerr := f.Close(); cerr != nil {
			log.Warn("closing queued message", "error", cerr)
		}
	}
	defer closeBody()

	start := time.Now()
	err = smarthost.Deliver(ctx, route, smarthost.Message{
		From: meta.Envelope.From,
		To:   meta.Envelope.To,
		Data: f,
		Helo: m.cfg.Service.Hostname,
	}, time.Duration(m.cfg.Limits.DeliveryTimeoutSec)*time.Second, m.tokens[route.Name])
	res := attemptResult{err: err, elapsed: time.Since(start)}
	closeBody()

	// Two outcomes mean "delivered, do not retry" while still carrying
	// something worth saying. Both become success here, because requeueing
	// either one would deliver the message a second time to the recipients
	// who already have it.
	var partial *smarthost.PartialError
	var quitErr *smarthost.QuitError
	switch {
	case errors.As(err, &partial):
		log.Warn("delivered, but the smarthost refused some recipients",
			"refused", len(partial.Rejected), "accepted", len(meta.Envelope.To)-len(partial.Rejected),
			"detail", partial.Error())
		// Counted for a notification's and a canary's own traffic too: unlike
		// delivered/bounced, this is not a tally of relay volume that mixing
		// in diagnostic mail would distort. It says an address is dead, and
		// that is worth hearing about whichever message found it.
		m.metrics.RecipientsRefused(meta.Envelope.Route, len(partial.Rejected))
		// Every refused address, not only the first. Recording one while
		// smtprelayd_recipients_refused_total counted them all left an
		// operator following that alert with fewer addresses on the detail
		// page than the alert claimed.
		res.partialCode, _ = extractSMTPError(partial.Rejected[0].Err)
		res.partialResponse = describeRefusals(partial.Rejected)
		res.err = nil
	case errors.As(err, &quitErr):
		// The smarthost took the message and only the goodbye went wrong.
		log.Warn("the smarthost accepted the message but the session did not close cleanly",
			"error", quitErr.Error())
		res.err = nil
	}
	return res, true
}

// record turns one attempt's result into the message's fate: removed,
// failed, or returned to the queue with a backoff, plus the counter and the
// journal row that go with it.
func (m *Manager) record(log *slog.Logger, meta *spool.Meta, res attemptResult) {
	err := res.err
	switch {
	case err == nil:
		log.Info("delivered", "attempts", meta.Attempts, "duration_ms", res.elapsed.Milliseconds(),
			"recipients", len(meta.Envelope.To))
		m.recordOutcome(meta, outcomeDelivered, nil)
		m.journal(log, meta, res.partialCode, res.partialResponse, store.ClassDelivered, nil)
		if err := m.spool.Remove(meta.ID); err != nil {
			log.Error("cannot remove delivered message", "error", err)
		}

	case isPermanent(err):
		log.Warn("permanent delivery failure", "attempts", meta.Attempts, "error", err.Error())
		m.recordOutcome(meta, outcomeBounced, err)
		code, resp := extractSMTPError(err)
		m.fail(log, meta, store.ClassPermanent, code, resp, err.Error())

	case m.now().After(meta.Expires):
		log.Warn("message expired in queue", "attempts", meta.Attempts, "error", err.Error())
		m.recordOutcome(meta, outcomeBounced, err)
		code, resp := extractSMTPError(err)
		m.fail(log, meta, store.ClassExpired, code, resp, "expired in queue: "+err.Error())

	default:
		m.deferRetry(log, meta, err)
	}
}

// deferRetry schedules the next attempt for a temporary failure, clamped to
// the message's own expiry so that a backoff cannot outlive it.
func (m *Manager) deferRetry(log *slog.Logger, meta *spool.Meta, err error) {
	delay := m.backoff(meta.Attempts)
	meta.LastError = err.Error()
	meta.NextAttempt = m.now().Add(delay)
	if meta.NextAttempt.After(meta.Expires) {
		meta.NextAttempt = meta.Expires
	}
	log.Info("delivery deferred", "attempts", meta.Attempts,
		"retry_in_s", int(delay.Seconds()), "error", err.Error())
	m.recordOutcome(meta, outcomeDeferred, err)
	code, resp := extractSMTPError(err)
	m.journal(log, meta, code, resp, store.ClassTemporary, &meta.NextAttempt)
	if err := m.spool.Release(meta); err != nil {
		log.Error("cannot update queued message", "error", err)
	}
}

// outcome is what one attempt ended in, as far as the counters care.
type outcome int

const (
	outcomeDelivered outcome = iota
	outcomeBounced           // permanent failure or expiry in queue
	outcomeDeferred          // temporary failure, retried later
)

// recordOutcome routes an attempt's outcome to the counters that describe
// that kind of message.
//
// A notification is postmaster mail the bounce notifier or the expiry
// watcher composed, and a canary is a probe the canary runner composed:
// neither is client traffic, so neither touches the route's own
// delivered/bounced/deferred counters, which would otherwise mix diagnostic
// mail into the numbers that describe the relay's real volume. Each has a
// counter of its own instead. The kinds diverge in fail(), not here: a
// canary's failure still feeds the bounce digest, a notification's never
// does, because that is how a notification loop would start.
func (m *Manager) recordOutcome(meta *spool.Meta, o outcome, err error) {
	route, origin := meta.Envelope.Route, meta.Envelope.Origin
	switch meta.Envelope.Kind {
	case spool.KindNotification:
		if o != outcomeDelivered {
			m.metrics.NotificationFailure()
		}
	case spool.KindCanary:
		if o == outcomeDelivered {
			m.metrics.CanaryDelivered(origin)
		} else {
			m.metrics.CanaryFailure(origin)
		}
	default:
		switch o {
		case outcomeDelivered:
			m.metrics.Delivered(route)
		case outcomeBounced:
			m.metrics.Bounced(route)
		case outcomeDeferred:
			m.metrics.Deferred(route)
			if isAuthFailure(err) {
				m.metrics.AuthFailure(route)
			}
		}
	}
}

// journal records one attempt in the history store. The write is best-effort
// -- the spool, not the journal, is what the message's fate depends on -- but
// a failure is not silent: it is logged and counted, because a database that
// stopped accepting writes otherwise shows up only as a dashboard that slowly
// empties, which nobody reports.
func (m *Manager) journal(log *slog.Logger, meta *spool.Meta, code int, resp string, class store.Class, next *time.Time) {
	if err := m.history.RecordAttempt(meta.ID, meta.Attempts, code, resp, class, next); err != nil {
		log.Warn("history journal write failed", "class", class, "error", err)
		m.metrics.JournalWriteFailure()
	}
}

// backoff walks the configured retry schedule and holds at its last entry.
func (m *Manager) backoff(attempt int) time.Duration {
	sched := m.cfg.Queue.RetryScheduleMin
	i := attempt - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sched) {
		i = len(sched) - 1
	}
	return time.Duration(sched[i]) * time.Minute
}

// hold puts a message back for a short while without touching the disk. Both
// callers are scheduling decisions of this process alone -- the route is
// paced, or no worker slot was free -- and neither offered the message to the
// smarthost, so nothing about it has changed that a restart needs to find.
// The attempt counter is deliberately left alone for the same reason: waiting
// for a slot must not consume the retry budget or bring the expiry forward.
// Persisting these holds cost one fsync per held message per tick, which is
// worst exactly when a smarthost is hanging and the queue behind it is
// deepest.
func (m *Manager) hold(meta *spool.Meta, d time.Duration) {
	until := m.now().Add(d)
	if until.After(meta.Expires) {
		// Past its own expiry the message could never be tried again and
		// would not be expired either, so nothing would ever clear it.
		until = meta.Expires
	}
	// The caller's copy is updated too, so it still describes what was
	// actually scheduled; only the disk is left alone.
	meta.NextAttempt = until
	m.spool.Defer(meta, until)
}

// failUnsendable is the terminal path for a message that failed before it
// could even be offered to a smarthost -- an unknown route, an unreadable
// body -- so there is no SMTP response to record, only the reason.
func (m *Manager) failUnsendable(log *slog.Logger, meta *spool.Meta, reason string) {
	meta.Attempts++
	m.recordOutcome(meta, outcomeBounced, nil)
	m.fail(log, meta, store.ClassPermanent, 0, reason, reason)
}

// fail is the terminal path for a message that will not be retried.
func (m *Manager) fail(log *slog.Logger, meta *spool.Meta, class store.Class, code int, resp, reason string) {
	m.journal(log, meta, code, resp, class, nil)
	// The message is moved aside into spool/failed rather than deleted, so
	// that nothing is lost without a trace, and reported through the bounce
	// digest via FailRecorder below.
	if err := m.spool.Fail(meta, reason); err != nil {
		log.Error("cannot move failed message aside", "error", err)
		return
	}
	// A notification message failing is never recorded as a bounce to
	// notify about: that is exactly how a notification loop would start. A
	// canary's failure is, deliberately -- being reported is its purpose.
	if meta.Envelope.Kind != spool.KindNotification && m.fails != nil {
		m.fails.RecordFail(meta.Envelope.Origin, meta.ID)
	}
}

func isPermanent(err error) bool {
	var pe *smarthost.PermError
	return errors.As(err, &pe)
}

func isAuthFailure(err error) bool {
	var ae *smarthost.AuthError
	return errors.As(err, &ae)
}

// maxPartialResponse bounds what the attempt row carries. The full list is
// always in the log; this is the copy the dashboard renders into one table
// cell, and a message to a large distribution list would otherwise make that
// cell the page.
const maxPartialResponse = 500

// describeRefusals renders every refused recipient for the attempt row,
// bounded. It drops whole entries rather than cutting mid-string: half an
// address still looks like an address, and an operator acting on one would be
// chasing a mailbox that does not exist. What was dropped is stated, so the
// count still agrees with the metric.
func describeRefusals(rejected []smarthost.Rejection) string {
	var b strings.Builder
	for i, r := range rejected {
		entry := r.String()
		if i > 0 {
			entry = "; " + entry
		}
		if b.Len()+len(entry) > maxPartialResponse {
			fmt.Fprintf(&b, " (and %d more, see the log)", len(rejected)-i)
			break
		}
		b.WriteString(entry)
	}
	return b.String()
}

// extractSMTPError tries to extract the SMTP response code and text from an
// error. Returns (0, err.Error()) when no textproto.Error is found in err's
// chain, so the attempt row always carries some description of the failure
// even when it did not come from an SMTP reply.
func extractSMTPError(err error) (int, string) {
	var te *textproto.Error
	if errors.As(err, &te) {
		return te.Code, te.Msg
	}
	return 0, err.Error()
}
