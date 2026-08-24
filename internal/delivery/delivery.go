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
	"sync"
	"time"

	"github.com/tokajer/smtprelayd/internal/authms365"
	"github.com/tokajer/smtprelayd/internal/bounce"
	"github.com/tokajer/smtprelayd/internal/canary"
	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/delivery/smarthost"
	"github.com/tokajer/smtprelayd/internal/metrics"
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

// Manager drains the spool into the configured routes.
type Manager struct {
	cfg      *config.Config
	spool    *spool.Spool
	store    *store.Store
	log      *slog.Logger
	metrics  *metrics.Registry
	notifier *bounce.Notifier
	canaries []*canary.Runner

	// routes holds the per-route concurrency budget, limits the per-route
	// messages per minute, tokens the OAuth2 source for xoauth2 routes.
	routes map[string]chan struct{}
	limits map[string]int
	tokens map[string]smarthost.TokenSource
	rate   *routeLimiter
	wg     sync.WaitGroup

	// lastFailedSweep is read and written only from Run's own goroutine.
	lastFailedSweep time.Time
}

// New builds the delivery manager. Each route gets its own concurrency budget
// so that one slow smarthost cannot starve the others.
func New(cfg *config.Config, sp *spool.Spool, log *slog.Logger, st *store.Store) (*Manager, error) {
	m := &Manager{
		cfg: cfg, spool: sp, store: st, log: log.With("component", "delivery"),
		routes: map[string]chan struct{}{},
		limits: map[string]int{},
		tokens: map[string]smarthost.TokenSource{},
		rate:   newRouteLimiter(),
	}
	routeNames := make([]string, 0, len(cfg.Routes))
	authTokens := map[string]*authms365.TokenSource{}
	for _, r := range cfg.Routes {
		routeNames = append(routeNames, r.Name)
		m.routes[r.Name] = make(chan struct{}, r.MaxConcurrent)
		m.limits[r.Name] = r.RateLimitPerMin
		if r.Auth != "xoauth2" {
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
		authTokens[r.Name] = ts
		m.warnSecretExpiry(r)
	}
	canaryNames := make([]string, 0, len(cfg.Canaries))
	for _, c := range cfg.Canaries {
		canaryNames = append(canaryNames, c.Name)
		m.canaries = append(m.canaries, canary.New(cfg, c, sp, st, log))
	}
	m.metrics = metrics.New(sp, routeNames, canaryNames, authTokens)
	m.notifier = bounce.New(cfg, sp, st, log)
	return m, nil
}

// Metrics returns the registry the /metrics endpoint reads. It is non-nil
// once New has returned successfully.
func (m *Manager) Metrics() *metrics.Registry {
	return m.metrics
}

// Notifier returns the bounce-digest notifier, for the caller to run as a
// background goroutine. It is non-nil once New has returned successfully,
// even if notifications are not configured: Notifier.Run then simply
// returns immediately.
func (m *Manager) Notifier() *bounce.Notifier {
	return m.notifier
}

// Canaries returns one Runner per configured [[canary]] entry, for the
// caller to run each as its own background goroutine. Empty if none are
// configured.
func (m *Manager) Canaries() []*canary.Runner {
	return m.canaries
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
// and only surfaces once mail is already queued behind it. Decided
// 2026-08-21: the caller aborts startup on a non-nil error rather than only
// logging it, so the failure is loud immediately instead of silent until a
// message arrives. Routes iterate in configuration order for a deterministic
// error when more than one is broken; a route with no cached source (auth
// other than xoauth2) is skipped, since there is nothing to verify over the
// network for a static credential.
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

// Run dispatches queued messages until ctx is cancelled, then waits for the
// attempts already in flight.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(pollInterval)
	defer t.Stop()

	for {
		for {
			meta, ok := m.spool.Claim(time.Now())
			if !ok {
				break
			}
			budget, ok := m.routes[meta.Envelope.Route]
			if !ok {
				m.log.Error("queued message references unknown route",
					"queue_id", meta.ID.String(), "route", meta.Envelope.Route)
				m.fail(meta, "route no longer configured")
				continue
			}
			// Pace before taking a worker slot, so that a throttled route
			// does not hold its whole concurrency budget waiting.
			if wait, ok := m.rate.allow(meta.Envelope.Route, m.limits[meta.Envelope.Route], time.Now()); !ok {
				m.hold(meta, wait)
				continue
			}
			select {
			case budget <- struct{}{}:
			case <-ctx.Done():
				_ = m.spool.Release(meta)
				m.wg.Wait()
				return
			}
			m.wg.Add(1)
			go func(meta *spool.Meta) {
				defer func() {
					<-budget
					m.wg.Done()
				}()
				m.attempt(ctx, meta)
			}(meta)
		}

		m.sweepFailed(time.Now())

		select {
		case <-ctx.Done():
			m.wg.Wait()
			return
		case <-t.C:
		}
	}
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

func (m *Manager) attempt(ctx context.Context, meta *spool.Meta) {
	log := m.log.With("queue_id", meta.ID.String(), "route", meta.Envelope.Route)

	route, ok := m.cfg.Route(meta.Envelope.Route)
	if !ok {
		m.fail(meta, "route no longer configured")
		return
	}
	f, err := m.spool.Open(meta.ID)
	if err != nil {
		log.Error("cannot open queued message", "error", err)
		m.fail(meta, "message body unreadable")
		return
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
	}, time.Duration(m.cfg.Limits.WriteTimeoutSec)*time.Second, m.tokens[route.Name])
	elapsed := time.Since(start)
	closeBody()

	// A notification message is postmaster mail the bounce notifier composed
	// itself, not client traffic: its outcome is kept out of the relay's own
	// delivered/bounced/deferred counters (which would otherwise mix the
	// two) and out of RecordFail (which is how a notification loop would
	// start) further down in fail(). A canary message is the same kind of
	// diagnostic traffic and is kept out of the route counters the same way,
	// but deliberately not out of RecordFail: unlike a notification, a
	// canary's whole purpose is to be reported through the bounce digest if
	// it fails, so RecordFail's gate in fail() checks Notification alone.
	isNotification := meta.Envelope.Notification
	isCanary := meta.Envelope.Canary

	meta.Attempts++
	switch {
	case err == nil:
		log.Info("delivered", "attempts", meta.Attempts, "duration_ms", elapsed.Milliseconds(),
			"recipients", len(meta.Envelope.To))
		switch {
		case isNotification:
			// A bounce digest's own delivery is not relay traffic.
		case isCanary:
			m.metrics.CanaryDelivered(meta.Envelope.Client)
		default:
			m.metrics.Delivered(meta.Envelope.Route)
		}
		_ = m.store.RecordAttempt(meta.ID.String(), meta.Attempts, 0, "", "delivered", nil)
		if err := m.spool.Remove(meta.ID); err != nil {
			log.Error("cannot remove delivered message", "error", err)
		}

	case isPermanent(err):
		log.Warn("permanent delivery failure", "attempts", meta.Attempts, "error", err.Error())
		switch {
		case isNotification:
			m.metrics.NotificationFailure()
		case isCanary:
			m.metrics.CanaryFailure(meta.Envelope.Client)
		default:
			m.metrics.Bounced(meta.Envelope.Route)
		}
		code, resp := extractSMTPError(err)
		_ = m.store.RecordAttempt(meta.ID.String(), meta.Attempts, code, resp, "permanent", nil)
		m.fail(meta, err.Error())

	case time.Now().After(meta.Expires):
		log.Warn("message expired in queue", "attempts", meta.Attempts, "error", err.Error())
		switch {
		case isNotification:
			m.metrics.NotificationFailure()
		case isCanary:
			m.metrics.CanaryFailure(meta.Envelope.Client)
		default:
			m.metrics.Bounced(meta.Envelope.Route)
		}
		code, resp := extractSMTPError(err)
		_ = m.store.RecordAttempt(meta.ID.String(), meta.Attempts, code, resp, "expired", nil)
		m.fail(meta, "expired in queue: "+err.Error())

	default:
		delay := m.backoff(meta.Attempts)
		meta.LastError = err.Error()
		meta.NextAttempt = time.Now().Add(delay)
		if meta.NextAttempt.After(meta.Expires) {
			meta.NextAttempt = meta.Expires
		}
		log.Info("delivery deferred", "attempts", meta.Attempts,
			"retry_in_s", int(delay.Seconds()), "error", err.Error())
		switch {
		case isNotification:
			m.metrics.NotificationFailure()
		case isCanary:
			m.metrics.CanaryFailure(meta.Envelope.Client)
		default:
			m.metrics.Deferred(meta.Envelope.Route)
			if isAuthFailure(err) {
				m.metrics.AuthFailure(meta.Envelope.Route)
			}
		}
		code, resp := extractSMTPError(err)
		_ = m.store.RecordAttempt(meta.ID.String(), meta.Attempts, code, resp, "temporary", &meta.NextAttempt)
		if err := m.spool.Release(meta); err != nil {
			log.Error("cannot update queued message", "error", err)
		}
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

// hold defers a message that hit the route rate limit. The attempt counter is
// deliberately left alone: the message was never offered to the smarthost, so
// pacing must not consume its retry budget or bring its expiry forward.
func (m *Manager) hold(meta *spool.Meta, d time.Duration) {
	meta.NextAttempt = time.Now().Add(d)
	if meta.NextAttempt.After(meta.Expires) {
		meta.NextAttempt = meta.Expires
	}
	if err := m.spool.Release(meta); err != nil {
		m.log.Error("cannot defer a rate limited message",
			"queue_id", meta.ID.String(), "error", err)
	}
}

func (m *Manager) fail(meta *spool.Meta, reason string) {
	// Phase 5 turns this into a DSN. Until then the message is moved aside
	// rather than deleted, so that nothing is lost without a trace.
	if err := m.spool.Fail(meta, reason); err != nil {
		m.log.Error("cannot move failed message aside", "queue_id", meta.ID.String(), "error", err)
		return
	}
	// A notification message failing is never recorded as a bounce to
	// notify about: that is exactly how a notification loop would start.
	if !meta.Envelope.Notification && m.notifier != nil {
		m.notifier.RecordFail(meta.Envelope.Client, meta.ID.String())
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

// extractSMTPError tries to extract the SMTP response code and text from an error.
// Returns (0, "") if no SMTP error is found.
func extractSMTPError(err error) (int, string) {
	var te *textproto.Error
	if errors.As(err, &te) {
		return te.Code, te.Msg
	}
	return 0, err.Error()
}
