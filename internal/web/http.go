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
// headers docs/SECURITY.md requires for it: a strict CSP with no inline
// scripts (there are none; the dashboard has no JavaScript), a frame-busting
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
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
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
