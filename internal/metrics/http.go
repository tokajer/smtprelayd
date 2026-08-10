// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package metrics

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"
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

// Serve runs the metrics HTTP listener until ctx is cancelled. There is no
// authentication and no TLS: per MEMORY.md section 7 Checkmk polling does not
// need a token, and the listener is expected to bind to loopback like the
// dashboard. Any path other than the configured one gets the ServeMux
// default of 404.
func Serve(ctx context.Context, addr, path string, reg *Registry, log *slog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle(path, reg)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

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
