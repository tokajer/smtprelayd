// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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
