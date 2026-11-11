// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package mailaddr

import (
	"strings"
	"testing"
	"unicode/utf8"
)

var addressSeeds = []string{
	"relay@example.at",
	"first.last+tag@sub.example.at",
	"\"quoted local\"@example.at",
	"m\xc3\xbcller@example.at",
	"m\xfcller@example.at",
	"\xff\xfe@example.at",
	"<a@example.at",
	"a>b@example.at",
	"a@b",
	"@example.at",
	"a@",
	"a@b..example",
	"a@.example",
	"a@example.at\r\nRCPT TO:<x@evil.example>",
	"a@example.at\rx",
	"a@example.at\nx",
	"a\x00@example.at",
	"a\x7f@example.at",
	strings.Repeat("a", 65) + "@example.at",
	"a@" + strings.Repeat("b", 256),
	strings.Repeat("a", 64) + "@" + strings.Repeat("b", 190) + ".at",
	"",
}

func FuzzCheckEnvelope(f *testing.F) {
	for _, s := range addressSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if CheckEnvelope(s) != nil {
			// Looser than ValidAddress by design, never stricter: an address
			// an operator may configure must be one the relay will carry.
			if ValidAddress(s) {
				t.Fatalf("ValidAddress(%q) holds but CheckEnvelope refuses it", s)
			}
			return
		}
		if len(s) > maxPathLen {
			t.Fatalf("CheckEnvelope accepted %d octets", len(s))
		}
		for i := 0; i < len(s); i++ {
			if c := s[i]; c < 0x20 || c == 0x7f {
				t.Fatalf("CheckEnvelope accepted a control character in %q", s)
			}
		}
		if at := strings.LastIndex(s, "@"); at <= 0 || at == len(s)-1 {
			t.Fatalf("CheckEnvelope accepted %q without local@domain", s)
		}
		// What the spool's JSON encoding would rewrite, and the delimiter
		// the listener parsed the path out of.
		if !utf8.ValidString(s) {
			t.Fatalf("CheckEnvelope accepted invalid UTF-8 %q", s)
		}
		if strings.ContainsAny(s, "<>") {
			t.Fatalf("CheckEnvelope accepted an angle bracket in %q", s)
		}
	})
}

func FuzzSplitMailbox(f *testing.F) {
	for _, s := range addressSeeds {
		f.Add(s)
		f.Add("Printer Vienna <" + s + ">")
	}
	for _, s := range []string{
		"\"Printer\" <relay@example.at>",
		"Printer <relay@example.at>, Other <other@example.at>",
		"g: relay@example.at;",
		"Printer\r\n <relay@example.at>",
		"Printer\x00 <relay@example.at>",
		"M\xc3\xbcller <relay@example.at>",
		"<relay@example.at",
		"relay@example.at>",
		"a<b> <relay@example.at>",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		display, addr, ok := SplitMailbox(s)
		if !ok {
			return
		}
		if !ValidAddress(addr) {
			t.Fatalf("SplitMailbox(%q) returned address %q, which ValidAddress refuses", s, addr)
		}
		for i := 0; i < len(display); i++ {
			if c := display[i]; c < 0x20 || c > 0x7e || c == '<' || c == '>' || c == '"' || c == '\\' {
				t.Fatalf("SplitMailbox(%q) returned display name %q with %q", s, display, c)
			}
		}
	})
}
