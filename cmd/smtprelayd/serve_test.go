// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/api"
	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
	"github.com/tokajer/smtprelayd/internal/web"
)

// serve starts the delivery manager, the notifier, the canaries and the
// expiry watcher before it binds the listeners, so a bind failure returns
// with all of them already running. Nothing on that path waits for them
// explicitly -- the deferred stop()+bg.Wait() is what cancels and collects
// them -- and if that ever stops being true the service hangs on a
// misconfigured port instead of reporting it.
func TestServeReturnsWhenTheListenerCannotBind(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	addr := occupied.Addr().String()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "smtprelayd.toml")
	body := fmt.Sprintf(`
[service]
data_dir = %q

[[listener]]
name = "smtp"
address = %q
tls = "none"

[[client]]
name = "printers"
cidr = ["10.10.5.0/24"]
route = "r"

[[route]]
name = "r"
default = true
host = "smtp.example"
auth = "none"
tls = "none"
`, dir, addr)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	ready := make(chan error, 1)
	errc := make(chan error, 1)
	start := time.Now()
	go func() { errc <- serve(context.Background(), cfgPath, false, ready) }()

	select {
	case err := <-errc:
		t.Logf("serve returned after %v with: %v", time.Since(start), err)
		if err == nil {
			t.Fatal("serve returned nil despite the bind failure")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not return after a bind failure -- the shutdown path hangs")
	}
}

// The dashboard and the JSON API share one socket, and the Host header is
// what completes the loopback trust boundary for both of them. It used to be
// applied inside web.Server.Handler(), which meant /api/v1/ inherited
// nothing -- and GET /api/v1/health deliberately needs no bearer token while
// reporting the version, the uptime, every route name and whether each route
// holds a valid token. A rebound page could read all of it.
func TestLoopbackHandlerGuardsBothTheDashboardAndTheAPI(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sp, err := spool.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir, log, 90, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := config.Defaults()
	cfg.Service.DataDir = dir
	reg := metrics.New(nil, sp, []string{"m365"}, nil, nil)
	ws, err := web.New(cfg, st, sp, reg, "test", log)
	if err != nil {
		t.Fatal(err)
	}
	h := loopbackHandler(ws, api.New(cfg, st, sp, reg, "test", log), log)

	// Both surfaces, because covering one and not the other is the defect.
	for _, path := range []string{"/queue", "/api/v1/health"} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = "rebind.attacker.example"
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("%s with a rebound Host: status %d, want %d",
				path, rec.Code, http.StatusMisdirectedRequest)
		}
		if strings.Contains(rec.Body.String(), "m365") {
			t.Errorf("%s with a rebound Host leaked a route name: %s", path, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		r = httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = "127.0.0.1:8025"
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Errorf("%s addressed to loopback: status %d, want 200", path, rec.Code)
		}
	}
}
