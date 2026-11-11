// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzParsePath(f *testing.F) {
	for _, s := range []string{
		"<user@example.at>",
		"<user@example.at> SIZE=1234 BODY=8BITMIME",
		"  <first.last+tag@sub.example.at>",
		"<>",
		"<\"quoted local\"@example.at>",
		"<m\xc3\xbcller@example.at>",
		"<a@b.example\r\nRCPT TO:<victim@example.net>>",
		"<a@b.example\nBcc: victim@example.net>",
		"<a@b.example\rx>",
		"<a\x00@b.example>",
		"<a@b.example\x1b>",
		"a@b.example",
		"<a@>",
		"<@b.example>",
		"<<a@b.example>>",
		"<<a@b.example>",
		"<a<b@c.example>",
		"<m\xfcller@example.at>",
		"<" + strings.Repeat("a", 65) + "@b.example>",
		"<a@" + strings.Repeat("b", 256) + ">",
		"<a@b..example>",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, arg string) {
		addr, _, err := parsePath(arg)
		if err != nil || addr == "" {
			return
		}
		// Properties of the result itself, not a restatement of the check
		// parsePath calls: whatever that check becomes, these must hold for
		// an address that is written back into MAIL FROM or RCPT TO.
		if !strings.Contains(arg, addr) {
			t.Fatalf("parsePath(%q) = %q, not part of its input", arg, addr)
		}
		if len(addr) > 254 {
			t.Fatalf("parsePath(%q) accepted %d octets", arg, len(addr))
		}
		if strings.ContainsAny(addr, "<>") {
			t.Fatalf("parsePath(%q) = %q contains an angle bracket", arg, addr)
		}
		// The spool stores the envelope as JSON, which would rewrite an
		// invalid octet as U+FFFD and so deliver to another address.
		if !utf8.ValidString(addr) {
			t.Fatalf("parsePath(%q) = %q is not valid UTF-8", arg, addr)
		}
		for i := 0; i < len(addr); i++ {
			if c := addr[i]; c < 0x20 || c == 0x7f {
				t.Fatalf("parsePath(%q) = %q carries a control character", arg, addr)
			}
		}
	})
}
