// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package queueid

import "testing"

func TestParseRejectsPathTricks(t *testing.T) {
	// The queue ID becomes a file name, so anything that could escape the
	// spool directory must be refused before it gets there.
	for _, s := range []string{
		"../../etc/passwd", "..", "/absolute", "a/b", `a\b`, "",
		"lowercase1234567", "TOOSHORT", "AAAAAAAAAAAAAAAAA", "AAAAAAAA1AAAAAAA",
	} {
		if id, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted %q", s, id)
		}
	}
}

func TestNewRoundTrips(t *testing.T) {
	id, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if !id.Valid() {
		t.Fatalf("New produced an invalid id %q", id)
	}
	if _, err := Parse(id.String()); err != nil {
		t.Fatalf("Parse rejected a generated id %q: %v", id, err)
	}
}
