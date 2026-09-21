// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package api

import (
	"encoding/base64"
	"encoding/json"

	"github.com/tokajer/smtprelayd/internal/store"
)

// defaultLimit is this API's page size when a request names none.
//
// The ceiling is not this package's to choose: store.clampPaging caps every
// list query at store.MaxPageLimit whatever it is asked for, so a second
// constant here could only ever agree with it or lie about it. The same goes
// for how deep a cursor may page -- decodeCursor used to carry its own
// 1_000_000, which would have gone on being enforced after the store's had
// moved.
const defaultLimit = 100

// maxLimit and maxOffset are the store's own bounds under the names the
// handlers here use. They are aliases, never copies: the store clamps every
// list query to them regardless, and a second value here would go on being
// enforced after that one had moved.
const (
	maxLimit  = store.MaxPageLimit
	maxOffset = store.MaxOffset
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
	// Clamped here as well as in the store, and deliberately: the store
	// resets an out-of-range offset to the start, so a cursor left unclamped
	// would be echoed back into next_cursor naming a page the query never
	// served. Both clamps use store.MaxOffset, so they cannot disagree about
	// where the range ends.
	if c.Offset < 0 || c.Offset > maxOffset {
		c.Offset = 0
	}
	if c.Limit <= 0 || c.Limit > maxLimit {
		c.Limit = defaultLimit
	}
	return c
}
