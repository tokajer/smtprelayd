// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package metrics

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
)

// ServeHTTP renders the current metrics in Prometheus text exposition
// format. The request is never used to shape the response — every value
// exposed is either configuration data (route names) or an internal
// counter — so there is no injection surface here to defend against.
func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if req.Method == http.MethodHead {
		return
	}
	_, _ = io.WriteString(w, r.text())
}

// requireToken wraps the exposition in bearer-token authentication with read
// scope. It is applied only to a listener that binds beyond loopback: on
// loopback the endpoint stays open, per the original Checkmk decision, and
// the process boundary is the control.
//
// There is no rate limiting on failures here, unlike the JSON API. This
// endpoint exposes counters, not message content, and its whole point is to
// be polled continuously — locking a monitoring system out after five bad
// requests would turn a credential mistake into an alerting outage. The
// failures are logged and counted instead.
func requireToken(cfg *config.Config, next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t, ok := cfg.MatchToken(bearerToken(r))
		if !ok || !config.ScopeSatisfies(t.Scope, "read") {
			// The source address is logged, never made a metric label:
			// an address chosen by whoever is failing to authenticate
			// would let them grow the exposition without bound.
			log.Warn("metrics authentication failed", "source", sourceAddr(r))
			w.Header().Set("WWW-Authenticate", `Bearer realm="smtprelayd"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireLoopbackHost is the loopback listener's counterpart to requireToken:
// where a public listener authenticates with a bearer token, a loopback one
// authenticates by being unreachable — except from a browser, which resolves
// names on the attacker's behalf. A page the operator visits can rebind a name
// it controls to 127.0.0.1 and read the exposition, which carries route names
// and queue depths.
//
// Applied only to a loopback listener. A public one is reached by its real
// name or address, so requiring loopback in the Host header there would refuse
// every legitimate scrape.
func requireLoopbackHost(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !config.IsLoopbackHostHeader(r.Host) {
			log.Warn("metrics request with a non-loopback Host header rejected",
				"host", r.Host, "source", sourceAddr(r))
			http.Error(w, "this endpoint only answers requests addressed to loopback",
				http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// sourceAddr strips the port from RemoteAddr. X-Forwarded-For is deliberately
// not consulted, for the same reason the API does not: without a documented
// proxy in front of this listener it would let any client name any source.
func sourceAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Serve runs the metrics HTTP listener until ctx is cancelled. Any path other
// than the configured one gets the ServeMux default of 404.
//
// A loopback listener is served in the clear with no authentication, which is
// what Checkmk polling on the host itself wants. A listener that binds beyond
// loopback is served over TLS and requires a read-scope bearer token;
// config.Validate refuses such an address unless both a token and a
// certificate exist, so the two halves cannot disagree about which mode this
// is in.
func Serve(ctx context.Context, cfg *config.Config, reg *Registry, log *slog.Logger) error {
	addr := cfg.Metrics.Address
	var handler http.Handler = reg

	public := true
	if host, _, err := net.SplitHostPort(addr); err == nil {
		public = !config.IsLoopbackHost(host)
	}
	if public {
		handler = requireToken(cfg, handler, log)
	} else {
		handler = requireLoopbackHost(handler, log)
	}

	mux := http.NewServeMux()
	mux.Handle(cfg.Metrics.Path, handler)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		// Tighter than the dashboard's: the exposition is rendered from
		// in-memory counters and one spool index walk, and the request body is
		// always empty. Idle is long enough for a scraper's keep-alive to
		// survive a one-minute poll interval.
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	errCh := make(chan error, 1)
	if public {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("metrics: loading TLS certificate: %w", err)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		log.Info("metrics listener requires a read-scope bearer token", "address", addr)
		go func() { errCh <- srv.ListenAndServeTLS("", "") }()
	} else {
		go func() { errCh <- srv.ListenAndServe() }()
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics listener failed", "error", err)
			return err
		}
		return nil
	}
}
