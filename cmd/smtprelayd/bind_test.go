// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package main

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/tokajer/smtprelayd/internal/config"
)

// devNull keeps the note lines out of the test output.
func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestCheckBindRejectsUnassignableAddress(t *testing.T) {
	// TEST-NET-1, which is guaranteed not to be assigned to this host.
	cfg := &config.Config{Listeners: []config.Listener{{Name: "smtp", Address: "192.0.2.1:2525"}}}

	err := checkBind(cfg, devNull(t))
	if err == nil {
		t.Fatal("checkBind accepted an address that is not assignable")
	}
	if !strings.Contains(err.Error(), "listener smtp") {
		t.Errorf("error does not name the listener: %v", err)
	}
}

func TestCheckBindAcceptsAssignableAddress(t *testing.T) {
	cfg := &config.Config{Listeners: []config.Listener{{Name: "smtp", Address: "127.0.0.1:0"}}}

	if err := checkBind(cfg, devNull(t)); err != nil {
		t.Fatalf("checkBind rejected a bindable address: %v", err)
	}
}

// An instance already running must not make its own configuration look broken.
func TestCheckBindToleratesAddressInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cfg := &config.Config{Listeners: []config.Listener{{Name: "smtp", Address: ln.Addr().String()}}}

	if err := checkBind(cfg, devNull(t)); err != nil {
		t.Fatalf("checkBind failed on an address held by a running instance: %v", err)
	}
}

func TestCheckBindSkipsDisabledEndpoints(t *testing.T) {
	cfg := &config.Config{
		Listeners: []config.Listener{{Name: "smtp", Address: "127.0.0.1:0"}},
		Web:       config.Web{Address: "192.0.2.1:8025", Enabled: false},
		Metrics:   config.Metrics{Address: "192.0.2.1:9025", Enabled: false},
	}

	if err := checkBind(cfg, devNull(t)); err != nil {
		t.Fatalf("checkBind verified a disabled endpoint: %v", err)
	}
}
