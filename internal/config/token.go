// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

// Scope values a token may carry. Defined here once so that every place
// comparing against one of them -- the validator, the API's auth check, the
// metrics endpoint, the token subcommand -- shares the same two spellings
// rather than each holding its own copy of the literal.
const (
	ScopeRead  = "read"
	ScopeAdmin = "admin"
)

// ScopeSatisfies reports whether a token's scope permits an action that
// requires need. admin satisfies everything; read only satisfies itself.
func ScopeSatisfies(have, need string) bool {
	return have == ScopeAdmin || have == need
}

// HasReadableToken reports whether any configured token can be used for a
// read-scope request. Used to refuse a configuration that exposes an
// authenticated endpoint beyond loopback with no credential that could ever
// reach it.
func (c *Config) HasReadableToken() bool {
	for _, t := range c.Web.Tokens {
		if ScopeSatisfies(t.Scope, ScopeRead) {
			return true
		}
	}
	return false
}
