// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package loopback decides whether a host or an HTTP Host header names the
// local machine only. config's validator and the HTTP listeners that bind to
// loopback both need the same answer, so it lives in one stdlib-only leaf
// rather than being exported from config for every caller to import that
// package just to ask this question.
package loopback

import (
	"net"
	"net/netip"
	"strings"
)

// Host reports whether host names the local machine only.
func Host(host string) bool {
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// HostHeader reports whether an HTTP Host header names the local machine. It
// exists because "the listener is bound to loopback" and "this request was
// addressed to loopback" are different statements: a browser resolves a name
// the page controls, so a DNS rebind reaches a loopback listener with an
// attacker's name in the Host header, from inside the boundary the loopback
// bind was supposed to be.
//
// The header may carry a port or not, and an IPv6 literal arrives in
// brackets, so both shapes are reduced to a bare host before the same
// loopback test Host uses.
func HostHeader(hostHeader string) bool {
	h := hostHeader
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	} else {
		h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	}
	return Host(h)
}
