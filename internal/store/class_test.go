// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package store

import "testing"

// TestClassAndStatusStringsArePinned guards the on-disk class strings and the
// class->status mapping the dashboard and the API both render from: a typo in
// either is a silent behaviour change, not a compile error.
func TestClassAndStatusStringsArePinned(t *testing.T) {
	cases := []struct {
		class  Class
		string string
		status string
	}{
		{ClassDelivered, "delivered", "delivered"},
		{ClassTemporary, "temporary", "deferred"},
		{ClassPermanent, "permanent", "bounced"},
		{ClassExpired, "expired", "bounced"},
		{ClassRemoved, "removed", "removed"},
	}
	for _, c := range cases {
		if string(c.class) != c.string {
			t.Errorf("Class %v = %q, want %q", c.class, string(c.class), c.string)
		}
		if got := classToStatus(c.class, true); got != c.status {
			t.Errorf("classToStatus(%q, true) = %q, want %q", c.class, got, c.status)
		}
	}
	if got := classToStatus("", false); got != "queued" {
		t.Errorf(`classToStatus("", false) = %q, want "queued"`, got)
	}
	if got := classToStatus("unknown", true); got != "deferred" {
		t.Errorf(`classToStatus("unknown", true) = %q, want "deferred"`, got)
	}
}
