// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// MatchToken compares a presented bearer token against every configured
// digest in constant time and returns the token it matched. Every candidate
// is compared, not just until the first match, so the time taken does not
// reveal how many tokens were tried before one (if any) succeeded.
//
// This lives here, next to the digests themselves, because both the JSON API
// and the metrics endpoint authenticate against the same list. Two
// implementations of one constant-time comparison is how one of them
// eventually stops being constant-time.
func (c *Config) MatchToken(presented string) (Token, bool) {
	if presented == "" {
		return Token{}, false
	}
	sum := sha256.Sum256([]byte(presented))
	digest := []byte(strings.ToLower(hex.EncodeToString(sum[:])))

	var found Token
	ok := false
	for _, t := range c.Web.Tokens {
		want := []byte(strings.ToLower(t.SHA256))
		if len(want) != len(digest) {
			continue
		}
		if subtle.ConstantTimeCompare(digest, want) == 1 {
			found, ok = t, true
		}
	}
	return found, ok
}

// ScopeSatisfies reports whether a token's scope permits an action that
// requires need. admin satisfies everything; read only satisfies itself.
func ScopeSatisfies(have, need string) bool {
	return have == "admin" || have == need
}

// HasReadableToken reports whether any configured token can be used for a
// read-scope request. Used to refuse a configuration that exposes an
// authenticated endpoint beyond loopback with no credential that could ever
// reach it.
func (c *Config) HasReadableToken() bool {
	for _, t := range c.Web.Tokens {
		if ScopeSatisfies(t.Scope, "read") {
			return true
		}
	}
	return false
}
