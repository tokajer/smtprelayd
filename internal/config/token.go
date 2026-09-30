// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

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
