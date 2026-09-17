// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// tokenBytes is the entropy behind one API token. docs/guides/SECURITY.md
// specifies 256 bits, which is also the digest width, so neither half of the
// pair is the weaker one.
const tokenBytes = 32

// newToken prints a fresh API token and the digest to configure it with.
//
// The token itself is never stored anywhere by this command and never
// reaches the configuration: only its SHA-256 digest does, which is what
// config.MatchToken compares against. That is the whole point of the
// arrangement — a configuration file that leaks does not hand over a working
// credential — and it is why the token is printed once and cannot be
// recovered afterwards.
func newToken(scope string, out io.Writer) error {
	switch scope {
	case "read", "admin":
	default:
		return fmt.Errorf("token new: scope must be read or admin, got %q", scope)
	}

	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("token new: %w", err)
	}
	// RawURLEncoding: no padding and no "+" or "/", so the value survives an
	// Authorization header, a shell command line and a password manager
	// unchanged.
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	digest := hex.EncodeToString(sum[:])

	fmt.Fprintf(out, "token:  %s\n", token)
	fmt.Fprintf(out, "sha256: %s\n\n", digest)
	fmt.Fprintf(out, "The token is shown once and is not stored. Put it in a password manager now;\n"+
		"it cannot be recovered from the configuration, which holds only the digest.\n\n")
	fmt.Fprintf(out, "Add to the configuration, renaming it after whoever will use it:\n\n")
	fmt.Fprintf(out, "[[web.token]]\nname   = \"changeme\"\nscope  = %q\nsha256 = %q\n\n", scope, digest)
	fmt.Fprintf(out, "Then restart the service and try it:\n")
	fmt.Fprintf(out, "  curl -H \"Authorization: Bearer %s\" http://127.0.0.1:8025/api/v1/queue\n", token)
	return nil
}
