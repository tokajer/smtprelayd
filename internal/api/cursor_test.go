// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package api

import "testing"

// An offset past the end costs SQLite a full scan of the result set before
// it can return nothing, so an unbounded one lets an authenticated caller
// force a table scan per request.
func TestDecodeCursorBoundsTheOffset(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{0, 0},
		{500, 500},
		{maxOffset, maxOffset},
		{maxOffset + 1, 0},
		{1 << 62, 0},
		{-1, 0},
	} {
		got := decodeCursor(encodeCursor(pageCursor{Offset: tc.in, Limit: 50}))
		if got.Offset != tc.want {
			t.Errorf("offset %d decoded to %d, want %d", tc.in, got.Offset, tc.want)
		}
	}
}
