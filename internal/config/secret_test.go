// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

import (
	"runtime"
	"strings"
	"testing"
)

// A secret must never be readable from the configuration file itself: only a
// reference to where the real value lives is accepted.
func TestSecretResolveRejectsLiteralValue(t *testing.T) {
	s := &Secret{ref: "hunter2"}
	err := s.resolve("test.secret")
	if err == nil {
		t.Fatal("expected a literal secret value to be rejected")
	}
	const want = "dpapi:"
	if got := err.Error(); !strings.Contains(got, want) {
		t.Fatalf("error %q does not mention the %q option", got, want)
	}
}

// On a platform without DPAPI a dpapi: reference must fail clearly at load
// time, naming the field that failed, not silently resolve to an empty
// secret or panic.
func TestSecretResolveDPAPIUnsupportedOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("DPAPI is available on Windows")
	}
	s := &Secret{ref: "dpapi:/some/path"}
	err := s.resolve("route x oauth2.client_secret")
	if err == nil {
		t.Fatal("expected an error resolving a dpapi: reference on a non-Windows build")
	}
	const want = "route x oauth2.client_secret"
	if got := err.Error(); !strings.Contains(got, want) {
		t.Fatalf("error %q does not mention the field name %q", got, want)
	}
}
