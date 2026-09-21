// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/httpx"
)

// dashboardPages is the dashboard's read-only page set: the template each one
// renders, the path it answers on, and the handler that binds the two.
//
// One table rather than three lists. Adding a page used to mean naming it in
// the template list in New, adding a route here, and writing the handler --
// and a page added to two of the three is silent: a template parsed and never
// served, or a route that renders nothing. It is the shape the command set in
// cmd/smtprelayd and the metric families in internal/metrics already use.
//
// Only the read-only pages belong here. The state-changing POST endpoints and
// the static assets are registered explicitly below, because each carries its
// own CSRF action name or content type and gains nothing from a table.
var dashboardPages = []struct {
	name    string // template base name, and the key in Server.tmpl
	path    string // ServeMux pattern, method included
	handler func(*Server, http.ResponseWriter, *http.Request)
}{
	{"queue", "GET /queue", (*Server).handleQueue},
	{"search", "GET /search", (*Server).handleSearch},
	{"bounces", "GET /bounces", (*Server).handleBounces},
	{"message", "GET /messages/{id}", (*Server).handleMessage},
	{"routes", "GET /routes", (*Server).handleRoutes},
	{"config", "GET /config", (*Server).handleConfig},
}

// Handler returns the dashboard's HTTP handler, wrapped with the security
// headers docs/guides/SECURITY.md requires for it: a strict CSP that allows scripts
// only from the dashboard's own origin (vendored htmx and the queue page's
// own script, both served from /static/, are the only two and neither needs
// inline script or eval), a frame-busting header, MIME sniffing turned off,
// and a conservative referrer policy.
//
// The loopback Host-header check is deliberately not here. It belongs to the
// listener rather than to one of the two handlers mounted on it: this
// dashboard shares its socket with the JSON API, and wrapping only this
// handler left /api/v1/ uncovered. cmd/smtprelayd applies
// httpx.RequireLoopbackHost to the combined mux; see the note on that
// function.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/queue", http.StatusFound)
	})
	for _, p := range dashboardPages {
		h := p.handler
		mux.HandleFunc(p.path, func(w http.ResponseWriter, r *http.Request) { h(s, w, r) })
	}
	mux.HandleFunc("POST /queue/requeue", s.handleQueueRequeue)
	mux.HandleFunc("POST /queue/delete", s.handleQueueDelete)
	mux.HandleFunc("POST /messages/{id}/requeue", s.handleRequeueAction)
	mux.HandleFunc("POST /messages/{id}/delete", s.handleDeleteAction)
	mux.HandleFunc("GET /static/style.css", s.handleStyle)
	mux.HandleFunc("GET /static/htmx.min.js", s.handleHTMXScript)
	mux.HandleFunc("GET /static/queue.js", s.handleQueueScript)
	return securityHeaders(mux)
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

// Serve runs the dashboard HTTP listener until ctx is cancelled, always in
// plaintext HTTP.
//
// It is never HTTPS because config.Validate refuses a non-loopback
// web.address outright: the dashboard has no authentication, so loopback is
// its trust boundary and there is no address for a certificate to
// authenticate to. This used to branch on cfg.TLS.CertFile being set, which
// is the wrong question — that field is populated as soon as any *SMTP*
// listener uses TLS, so configuring mail TLS silently turned the dashboard
// into HTTPS on loopback and an operator following CONFIGURATION.md to
// http://127.0.0.1:8025 got a handshake error with nothing explaining it.
//
// metrics.Serve makes the same decision from the address, which is the rule
// that actually matters; it still has a TLS branch because a metrics
// listener may legitimately bind beyond loopback behind a bearer token.
//
// The socket comes from Listen, bound by the caller beforehand, so that an
// address already in use is a startup error the caller sees synchronously
// rather than a line in the log after the service has reported itself
// started.
func Serve(ctx context.Context, ln net.Listener, handler http.Handler, log *slog.Logger) error {
	srv := &http.Server{
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

	return httpx.Serve(ctx, srv, func() error { return srv.Serve(ln) }, "web", log)
}

// Listen binds the dashboard's socket. Split from Serve for the reason
// listener.Set.Bind is split from Run: a port already in use has to fail
// startup, and on Windows fail it before the SCM is told the service started.
func Listen(cfg *config.Config) (net.Listener, error) {
	ln, err := net.Listen("tcp", cfg.Web.Address)
	if err != nil {
		return nil, fmt.Errorf("web: %w", err)
	}
	return ln, nil
}
