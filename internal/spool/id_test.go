// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package spool

import "testing"

func TestParseIDRejectsPathTricks(t *testing.T) {
	// The queue ID becomes a file name, so anything that could escape the
	// spool directory must be refused before it gets there.
	for _, s := range []string{
		"../../etc/passwd", "..", "/absolute", "a/b", `a\b`, "",
		"lowercase1234567", "TOOSHORT", "AAAAAAAAAAAAAAAAA", "AAAAAAAA1AAAAAAA",
	} {
		if id, err := ParseID(s); err == nil {
			t.Errorf("ParseID(%q) accepted %q", s, id)
		}
	}
}

func TestNewIDRoundTrips(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if !id.valid() {
		t.Fatalf("NewID produced an invalid id %q", id)
	}
	if _, err := ParseID(id.String()); err != nil {
		t.Fatalf("ParseID rejected a generated id %q: %v", id, err)
	}
}
