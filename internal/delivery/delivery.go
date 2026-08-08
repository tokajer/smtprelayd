// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package delivery runs the delivery workers and retry scheduling.
package delivery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/tokajer/smtprelayd/internal/authms365"
	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/delivery/smarthost"
	"github.com/tokajer/smtprelayd/internal/spool"
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
	cfg   *config.Config
	spool *spool.Spool
	log   *slog.Logger

	// routes holds the per-route concurrency budget, limits the per-route
	// messages per minute, tokens the OAuth2 source for xoauth2 routes.
	routes map[string]chan struct{}
	limits map[string]int
	tokens map[string]smarthost.TokenSource
	rate   *routeLimiter
	wg     sync.WaitGroup
}

// New builds the delivery manager. Each route gets its own concurrency budget
// so that one slow smarthost cannot starve the others.
func New(cfg *config.Config, sp *spool.Spool, log *slog.Logger) (*Manager, error) {
	m := &Manager{
		cfg: cfg, spool: sp, log: log.With("component", "delivery"),
		routes: map[string]chan struct{}{},
		limits: map[string]int{},
		tokens: map[string]smarthost.TokenSource{},
		rate:   newRouteLimiter(),
	}
	for _, r := range cfg.Routes {
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

		select {
		case <-ctx.Done():
			m.wg.Wait()
			return
		case <-t.C:
		}
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
	defer f.Close()

	start := time.Now()
	err = smarthost.Deliver(ctx, route, smarthost.Message{
		From: meta.Envelope.From,
		To:   meta.Envelope.To,
		Data: f,
		Helo: m.cfg.Service.Hostname,
	}, time.Duration(m.cfg.Limits.WriteTimeoutSec)*time.Second, m.tokens[route.Name])
	elapsed := time.Since(start)

	meta.Attempts++
	switch {
	case err == nil:
		log.Info("delivered", "attempts", meta.Attempts, "duration_ms", elapsed.Milliseconds(),
			"recipients", len(meta.Envelope.To))
		if err := m.spool.Remove(meta.ID); err != nil {
			log.Error("cannot remove delivered message", "error", err)
		}

	case isPermanent(err):
		log.Warn("permanent delivery failure", "attempts", meta.Attempts, "error", err.Error())
		m.fail(meta, err.Error())

	case time.Now().After(meta.Expires):
		log.Warn("message expired in queue", "attempts", meta.Attempts, "error", err.Error())
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
	}
}

func isPermanent(err error) bool {
	var pe *smarthost.PermError
	return errors.As(err, &pe)
}
