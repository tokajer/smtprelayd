// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
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

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

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
