// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"strings"
	"testing"
)

func TestParsePathRejectsInjection(t *testing.T) {
	// Every one of these has been used at some point to smuggle a second
	// recipient or an extra header past a relay.
	bad := []string{
		"<a@b.example\r\nRCPT TO:<victim@example.net>>",
		"<a@b.example\nBcc: victim@example.net>",
		"<a\x00@b.example>",
		"<a@b.example\x1b>",
		"a@b.example",
		"<a@>",
		"<@b.example>",
		"<" + strings.Repeat("a", 65) + "@b.example>",
		"<a@" + strings.Repeat("b", 256) + ">",
		"<a@b..example>",
		"<a@.example>",
	}
	for _, in := range bad {
		if addr, _, err := parsePath(in); err == nil {
			t.Errorf("parsePath(%q) accepted %q, want error", in, addr)
		}
	}
}

func TestParsePathAccepts(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"<user@example.at>", "user@example.at"},
		{"<user@example.at> SIZE=1234", "user@example.at"},
		{"  <first.last+tag@sub.example.at>", "first.last+tag@sub.example.at"},
		{"<>", ""},
	}
	for _, c := range cases {
		got, _, err := parsePath(c.in)
		if err != nil {
			t.Fatalf("parsePath(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("parsePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParsePathSizeParameter(t *testing.T) {
	_, params, err := parsePath("<a@b.example> SIZE=42 BODY=8BITMIME")
	if err != nil {
		t.Fatal(err)
	}
	if len(params) != 2 || params[0] != "SIZE=42" {
		t.Fatalf("params = %v", params)
	}
}
