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

	"github.com/tokajer/smtprelayd/internal/authms365"
	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/delivery/smarthost"
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/ratelimit"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// pollInterval bounds how long a freshly queued message waits before a worker
// notices it. Enqueue also signals the dispatcher, so this only matters after
// a restart or a missed wakeup.
const pollInterval = 5 * time.Second

// secretExpiryWarning is how far ahead an expiring client secret is announced.
// Renewing one needs an administrator with directory rights, which is rarely a
// same-day operation.
const secretExpiryWarning = 30 * 24 * time.Hour

// FailRecorder is told about every message that failed permanently or
// expired, once it has been moved to spool/failed. It is the whole of what
// this package needs from the bounce notifier: declaring it here, on the
// consumer side, keeps internal/bounce -- and behind it selfmail and the
// message composition path -- out of the delivery manager's imports for the
// sake of one callback.
type FailRecorder interface {
	RecordFail(client, queueID string)
}

// Manager drains the spool into the configured routes.
type Manager struct {
	cfg     *config.Config
	spool   *spool.Spool
	store   *store.Store
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

	// lastFailedSweep and quotaWarned are read and written only from Run's
	// own goroutine.
	lastFailedSweep time.Time
	quotaWarned     bool
}

// New builds the delivery manager. Each route gets its own concurrency budget
// so that one slow smarthost cannot starve the others.
//
// reg and fails are injected rather than built here: the registry is shared
// with the listener, the dashboard and the metrics endpoint, and the notifier
// runs on its own goroutine that the caller owns, so neither is this
// package's to construct. fails may be nil, in which case permanent failures
// are moved aside without anyone being told.
func New(cfg *config.Config, sp *spool.Spool, log *slog.Logger, st *store.Store, reg *metrics.Registry, fails FailRecorder) (*Manager, error) {
	m := &Manager{
		cfg: cfg, spool: sp, store: st, log: log.With("component", "delivery"),
		metrics: reg, fails: fails,
		routes: map[string]chan struct{}{},
		limits: map[string]int{},
		tokens: map[string]smarthost.TokenSource{},
		rate:   ratelimit.New(),
	}
	for _, r := range cfg.Routes {
		m.routes[r.Name] = make(chan struct{}, r.MaxConcurrent)
		m.limits[r.Name] = r.RateLimitPerMin
		if r.Auth != config.AuthXOAUTH2 {
			continue
		}
		ts, err := authms365.New(authms365.Options{
			TenantID: r.OAuth2.TenantID,
			ClientID: r.OAuth2.ClientID,
			Secret:   r.OAuth2.ClientSecret.Value(),
			Scope:    r.OAuth2.Scope,
		})
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", r.Name, err)
		}
		m.tokens[r.Name] = ts
		m.metrics.RegisterTokenAger(r.Name, ts)
		m.warnSecretExpiry(r)
	}
	return m, nil
}

// warnSecretExpiry surfaces an expiring client secret at startup. Until the
// metrics endpoint exists this log line is the only warning an operator gets
// before every delivery starts failing authentication.
func (m *Manager) warnSecretExpiry(r config.Route) {
	exp, ok := r.OAuth2.SecretExpiry()
	if !ok {
		return
	}
	switch d := time.Until(exp); {
	case d <= 0:
		m.log.Error("client secret has expired", "route", r.Name, "expired", r.OAuth2.SecretExpires)
	case d < secretExpiryWarning:
		m.log.Warn("client secret expires soon", "route", r.Name,
			"expires", r.OAuth2.SecretExpires, "days_left", int(d.Hours()/24))
	}
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

		m.sweepFailed(time.Now())
		m.sweepHistory(time.Now())
		m.checkQuota()

		select {
		case <-ctx.Done():
			m.wg.Wait()
			return
		case <-t.C:
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
		batch := m.spool.ClaimBatch(time.Now(), claimBatchSize, skip)
		if len(batch) == 0 {
			return true
		}
		for i, meta := range batch {
			if !m.dispatchOne(ctx, meta, saturated) {
				// Cancelled: every message still in this batch is leased and
				// has to go back, or it stays in flight until the restart.
				m.releaseFrom(batch, i)
				return false
			}
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
func (m *Manager) releaseFrom(batch []*spool.Meta, first int) {
	for _, meta := range batch[first:] {
		_ = m.spool.Release(meta)
	}
}

// dispatchOne hands one claimed message to a worker, or puts it back when it
// cannot be delivered now. It reports false only when ctx was cancelled, in
// which case the caller releases this message and the rest of its batch.
func (m *Manager) dispatchOne(ctx context.Context, meta *spool.Meta, saturated map[string]bool) bool {
	route := meta.Envelope.Route
	budget, ok := m.routes[route]
	if !ok {
		m.log.Error("queued message references unknown route",
			"queue_id", meta.ID.String(), "route", route)
		m.fail(meta, "route no longer configured")
		return true
	}
	// Pace before taking a worker slot, so that a throttled route does not
	// hold its whole concurrency budget waiting.
	if wait, ok := m.rate.Allow(route, m.limits[route], time.Now()); !ok {
		saturated[route] = true
		m.hold(meta, wait)
		return true
	}
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

// failedSweepInterval throttles the spool/failed retention sweep. The dispatch
// loop is the only thing already ticking over the spool's lifecycle, so the
// sweep hangs off it rather than adding a goroutine — but it walks a directory
// index, and the retention it enforces is measured in days, so running it on
// every poll would be pure waste.
const failedSweepInterval = time.Hour

func (m *Manager) sweepFailed(now time.Time) {
	if now.Sub(m.lastFailedSweep) < failedSweepInterval {
		return
	}
	m.lastFailedSweep = now
	if removed, freed := m.spool.SweepFailed(now); removed > 0 {
		m.log.Info("failed spool retention sweep",
			"removed", removed, "freed_bytes", freed)
	}
}

// sweepHistory runs the history store's retention delete here rather than
// letting it happen inside a journal write. The store keeps its own hourly
// gate, so calling it every tick costs one comparison; what matters is which
// goroutine pays when the gate opens. Measured at a million rows the delete
// took 15.6 seconds, and SQLite has a single writer -- from a delivery worker
// that stalled the worker and every other writer behind it.
func (m *Manager) sweepHistory(now time.Time) {
	if deleted := m.store.RetentionSweep(now); deleted > 0 {
		m.log.Info("history retention sweep", "deleted_rows", deleted)
	}
}

// checkQuota fetches the current quota state from the spool and reports it.
func (m *Manager) checkQuota() {
	used, quota, over := m.spool.QuotaWarning()
	m.reportQuota(used, quota, over)
}

// reportQuota logs the spool quota warning only on a transition. The
// dispatch loop polls every pollInterval (5s), so logging the current state
// on each poll rather than the edge would bury the one line an operator
// needs to notice under constant repetition.
func (m *Manager) reportQuota(used, quota int64, over bool) {
	switch {
	case over && !m.quotaWarned:
		var percent int64
		if quota > 0 {
			percent = used * 100 / quota
		}
		m.log.Warn("spool is filling up",
			"used_bytes", used, "max_bytes", quota, "percent", percent)
	case !over && m.quotaWarned:
		m.log.Info("spool is back below the quota warning threshold",
			"used_bytes", used, "max_bytes", quota)
	}
	m.quotaWarned = over
}

// attempt makes one delivery attempt and records what it ended in. The two
// halves are apart deliberately: send decides what happened on the wire,
// record decides what that means for the message, the counters and the
// journal, and neither needs to be read to follow the other.
func (m *Manager) attempt(ctx context.Context, meta *spool.Meta) {
	log := m.log.With("queue_id", meta.ID.String(), "route", meta.Envelope.Route)

	route, ok := m.cfg.Route(meta.Envelope.Route)
	if !ok {
		m.fail(meta, "route no longer configured")
		return
	}
	res, ok := m.send(ctx, log, route, meta)
	if !ok {
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
		m.fail(meta, "message body unreadable")
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
		m.journal(log, meta, res.partialCode, res.partialResponse, "delivered", nil)
		if err := m.spool.Remove(meta.ID); err != nil {
			log.Error("cannot remove delivered message", "error", err)
		}

	case isPermanent(err):
		log.Warn("permanent delivery failure", "attempts", meta.Attempts, "error", err.Error())
		m.recordOutcome(meta, outcomeBounced, err)
		code, resp := extractSMTPError(err)
		m.journal(log, meta, code, resp, "permanent", nil)
		m.fail(meta, err.Error())

	case time.Now().After(meta.Expires):
		log.Warn("message expired in queue", "attempts", meta.Attempts, "error", err.Error())
		m.recordOutcome(meta, outcomeBounced, err)
		code, resp := extractSMTPError(err)
		m.journal(log, meta, code, resp, "expired", nil)
		m.fail(meta, "expired in queue: "+err.Error())

	default:
		m.deferRetry(log, meta, err)
	}
}

// deferRetry schedules the next attempt for a temporary failure, clamped to
// the message's own expiry so that a backoff cannot outlive it.
func (m *Manager) deferRetry(log *slog.Logger, meta *spool.Meta, err error) {
	delay := m.backoff(meta.Attempts)
	meta.LastError = err.Error()
	meta.NextAttempt = time.Now().Add(delay)
	if meta.NextAttempt.After(meta.Expires) {
		meta.NextAttempt = meta.Expires
	}
	log.Info("delivery deferred", "attempts", meta.Attempts,
		"retry_in_s", int(delay.Seconds()), "error", err.Error())
	m.recordOutcome(meta, outcomeDeferred, err)
	code, resp := extractSMTPError(err)
	m.journal(log, meta, code, resp, "temporary", &meta.NextAttempt)
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
func (m *Manager) journal(log *slog.Logger, meta *spool.Meta, code int, resp, class string, next *time.Time) {
	if err := m.store.RecordAttempt(meta.ID.String(), meta.Attempts, code, resp, class, next); err != nil {
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
	until := time.Now().Add(d)
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

func (m *Manager) fail(meta *spool.Meta, reason string) {
	// Phase 5 turns this into a DSN. Until then the message is moved aside
	// rather than deleted, so that nothing is lost without a trace.
	if err := m.spool.Fail(meta, reason); err != nil {
		m.log.Error("cannot move failed message aside", "queue_id", meta.ID.String(), "error", err)
		return
	}
	// A notification message failing is never recorded as a bounce to
	// notify about: that is exactly how a notification loop would start. A
	// canary's failure is, deliberately -- being reported is its purpose.
	if meta.Envelope.Kind != spool.KindNotification && m.fails != nil {
		m.fails.RecordFail(meta.Envelope.Origin, meta.ID.String())
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

// extractSMTPError tries to extract the SMTP response code and text from an error.
// Returns (0, "") if no SMTP error is found.
func extractSMTPError(err error) (int, string) {
	var te *textproto.Error
	if errors.As(err, &te) {
		return te.Code, te.Msg
	}
	return 0, err.Error()
}
