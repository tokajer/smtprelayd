// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package api

import (
	"encoding/base64"
	"encoding/json"
)

const (
	defaultLimit = 100
	maxLimit     = 1000
)

// pageCursor is the opaque pagination state docs/guides/API.md calls "cursor":
// base64-encoded JSON carrying the next offset and the limit that produced
// it, so a client does not need to remember or resend its own limit.
type pageCursor struct {
	Offset int `json:"o"`
	Limit  int `json:"l"`
}

func encodeCursor(c pageCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor parses an opaque cursor. An empty, invalid or tampered cursor
// is not an error the caller must handle specially: it simply yields the
// zero offset with the default limit, so a mangled cursor costs a client its
// place in the list, not access to it.
func decodeCursor(s string) pageCursor {
	c := pageCursor{Limit: defaultLimit}
	if s == "" {
		return c
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return pageCursor{Limit: defaultLimit}
	}
	var parsed pageCursor
	if err := json.Unmarshal(b, &parsed); err != nil {
		return pageCursor{Limit: defaultLimit}
	}
	c = parsed
	if c.Offset < 0 {
		c.Offset = 0
	}
	if c.Limit <= 0 || c.Limit > maxLimit {
		c.Limit = defaultLimit
	}
	return c
}
