// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/tokajer/smtprelayd/internal/config"
)

// checkBind binds and immediately releases every address the daemon would
// bind. Validation can only prove an address is well formed; whether it is
// assignable on this host is knowable no other way, and getting that wrong
// turns a passing `check` into a service that fails on every restart.
func checkBind(cfg *config.Config, out *os.File) error {
	type target struct{ what, addr string }

	targets := make([]target, 0, len(cfg.Listeners)+2)
	for _, l := range cfg.Listeners {
		targets = append(targets, target{"listener " + l.Name, l.Address})
	}
	if cfg.Web.Enabled {
		targets = append(targets, target{"web", cfg.Web.Address})
	}
	if cfg.Metrics.Enabled {
		targets = append(targets, target{"metrics", cfg.Metrics.Address})
	}

	var fatal []string
	for _, t := range targets {
		ln, err := net.Listen("tcp", t.addr)
		if err == nil {
			_ = ln.Close()
			continue
		}
		switch {
		case isAddrInUse(err):
			// The normal case when validating the config of a running instance.
			fmt.Fprintf(out, "note: %s (%s) is already in use, not verified\n", t.what, t.addr)
		case errors.Is(err, os.ErrPermission):
			// The service reaches privileged ports through
			// CAP_NET_BIND_SERVICE; an unprivileged check must not call that
			// a broken configuration.
			fmt.Fprintf(out, "note: %s (%s) needs privileges to bind, not verified\n", t.what, t.addr)
		default:
			fatal = append(fatal, fmt.Sprintf("%s: %v", t.what, err))
		}
	}
	if len(fatal) > 0 {
		return fmt.Errorf("address not bindable:\n  - %s", strings.Join(fatal, "\n  - "))
	}
	return nil
}
