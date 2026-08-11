// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// Server serves the bearer-token-authenticated JSON API described in
// docs/API.md. It shares the dashboard's listener and its store, spool and
// metrics registry; nothing here owns them.
type Server struct {
	cfg     *config.Config
	store   *store.Store
	spool   *spool.Spool
	metrics *metrics.Registry
	version string
	log     *slog.Logger
	fails   *failLimiter
}

// New builds an API server. reg may be nil if metrics are disabled, in
// which case uptime reports zero and route health omits token age.
func New(cfg *config.Config, st *store.Store, sp *spool.Spool, reg *metrics.Registry, version string, log *slog.Logger) *Server {
	return &Server{
		cfg: cfg, store: st, spool: sp, metrics: reg, version: version,
		log: log.With("component", "api"), fails: newFailLimiter(),
	}
}

// tokenNameKey is the context key handleRequeue and handleDelete use to
// recover which token authorised the request, for the audit log.
type tokenNameKey struct{}

// Handler returns the API's HTTP handler, mounted by the caller under
// /api/v1/ (see cmd/smtprelayd, which strips that prefix before dispatch,
// so patterns here are registered without it). GET /health is the only
// endpoint reachable without a bearer token, per docs/API.md.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /bounces", s.auth("read", s.handleBounces))
	mux.HandleFunc("GET /messages", s.auth("read", s.handleMessages))
	mux.HandleFunc("GET /messages/{id}", s.auth("read", s.handleMessage))
	mux.HandleFunc("GET /queue", s.auth("read", s.handleQueue))
	mux.HandleFunc("POST /messages/{id}/requeue", s.auth("admin", s.handleRequeue))
	mux.HandleFunc("DELETE /messages/{id}", s.auth("admin", s.handleDelete))
	return jsonHeaders(mux)
}

func jsonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// auth wraps a handler with bearer-token validation, the failed-attempt rate
// limiter and the scope check, per docs/API.md: constant-time comparison,
// failures logged with the source address and counted in /metrics, missing
// or malformed token yields 401, insufficient scope yields 403.
func (s *Server) auth(need string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		source := sourceAddr(r)
		now := time.Now()

		if wait, blocked := s.fails.blocked(source, now); blocked {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			writeJSONError(w, http.StatusTooManyRequests, "too many failed authentication attempts")
			return
		}

		info, ok := checkToken(s.cfg, bearerToken(r))
		if !ok {
			s.fails.recordFailure(source, now)
			if s.metrics != nil {
				s.metrics.APIAuthFailure()
			}
			s.log.Warn("api auth failed", "source", source, "path", r.URL.Path)
			writeJSONError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		s.fails.recordSuccess(source)

		if !scopeSatisfies(info.Scope, need) {
			writeJSONError(w, http.StatusForbidden, "token scope does not permit this action")
			return
		}

		ctx := context.WithValue(r.Context(), tokenNameKey{}, info.Name)
		next(w, r.WithContext(ctx))
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) serverError(w http.ResponseWriter, endpoint string, err error) {
	s.log.Error("api query failed", "endpoint", endpoint, "error", err)
	writeJSONError(w, http.StatusInternalServerError, "internal error")
}

// redactSubject applies the same display policy as the dashboard: when
// retain_subjects is disabled, store.RecordMessage has already written an
// empty string for every row, so substituting a fixed marker here cannot
// under- or over-redact relative to what is actually in the database.
func (s *Server) redactSubject(subject string) string {
	if s.cfg.History.RetainSubjects {
		return subject
	}
	return "[redacted]"
}
