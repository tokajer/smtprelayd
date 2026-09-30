// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package ostrust

import (
	"strings"
	"testing"
)

// On a platform without DPAPI a dpapi: reference must fail clearly at load
// time, not silently resolve to an empty secret or panic.
func TestResolveDPAPISecretUnsupportedOffWindows(t *testing.T) {
	_, err := ResolveDPAPISecret("/does/not/matter")
	if err == nil {
		t.Fatal("expected an error resolving a dpapi: reference on a non-Windows build")
	}
	const want = "only supported on Windows"
	if got := err.Error(); !strings.Contains(got, want) {
		t.Fatalf("error %q does not mention %q", got, want)
	}
}
