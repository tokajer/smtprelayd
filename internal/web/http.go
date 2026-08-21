// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
)

// Handler returns the dashboard's HTTP handler, wrapped with the security
// headers docs/guides/SECURITY.md requires for it: a strict CSP that allows scripts
// only from the dashboard's own origin (htmx, vendored under /static/, is
// the only one and needs neither inline script nor eval), a frame-busting
// header, MIME sniffing turned off, and a conservative referrer policy.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/queue", http.StatusFound)
	})
	mux.HandleFunc("GET /queue", s.handleQueue)
	mux.HandleFunc("GET /search", s.handleSearch)
	mux.HandleFunc("GET /bounces", s.handleBounces)
	mux.HandleFunc("GET /messages/{id}", s.handleMessage)
	mux.HandleFunc("POST /messages/{id}/requeue", s.handleRequeueAction)
	mux.HandleFunc("POST /messages/{id}/delete", s.handleDeleteAction)
	mux.HandleFunc("GET /routes", s.handleRoutes)
	mux.HandleFunc("GET /config", s.handleConfig)
	mux.HandleFunc("GET /static/style.css", s.handleStyle)
	mux.HandleFunc("GET /static/htmx.min.js", s.handleHTMXScript)
	return s.requireLoopbackHost(securityHeaders(mux))
}

// requireLoopbackHost rejects a request whose Host header names anything but
// the local machine.
//
// config.Validate refuses a non-loopback web.address, which makes loopback the
// dashboard's authentication. A browser, however, sits inside that boundary: a
// page the operator visits can point a name it controls at 127.0.0.1 and then
// talk to the dashboard same-origin. That yields /queue, /search and /config,
// and the CSRF token can be lifted from a page and used to drive requeue and
// delete -- the token stops another origin from forging a request, not one
// that has legitimately read the page.
//
// The bind address is the server's own; the Host header is the client's claim.
// Only a request that addressed the loopback interface by name or literal is
// served, which a rebound name cannot do.
//
// The refusal names its own remedy rather than returning a bare 404, because
// the deployment config.Validate points operators at -- a reverse proxy that
// authenticates -- forwards the original Host by default and would otherwise
// fail here with nothing to go on.
func (s *Server) requireLoopbackHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !config.IsLoopbackHostHeader(r.Host) {
			s.log.Warn("dashboard request with a non-loopback Host header rejected",
				"host", r.Host, "source", r.RemoteAddr, "path", r.URL.Path)
			http.Error(w, "the dashboard only answers requests addressed to loopback; "+
				"a reverse proxy in front of it must set the Host header to the "+
				"configured web.address", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// Serve runs the dashboard HTTP listener until ctx is cancelled. Binding
// beyond loopback requires cfg.TLS to be configured — internal/config's
// validation refuses to start otherwise — in which case this serves HTTPS
// with that certificate instead of plaintext HTTP; a loopback address serves
// plain HTTP, matching the existing listener's own loopback exemption.
func Serve(ctx context.Context, cfg *config.Config, handler http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Addr:              cfg.Web.Address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		// A slow or vanished reader could otherwise hold a connection and its
		// handler goroutine indefinitely. The write budget is generous because
		// a search across a large history renders under it, not because a
		// dashboard page should ever take that long.
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	errCh := make(chan error, 1)
	if cfg.TLS.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("web: loading TLS certificate: %w", err)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
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
			log.Error("web listener failed", "error", err)
			return err
		}
		return nil
	}
}
