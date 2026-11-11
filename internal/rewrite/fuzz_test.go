// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package rewrite

import (
	"strings"
	"testing"

	"github.com/tokajer/smtprelayd/internal/config"
)

// headerSeeds are header blocks a device or an attacker has sent, or could.
var headerSeeds = []string{
	plainHeaders,
	"",
	"\r\n",
	"From: <invoice@example.at>\r\n\r\n",
	"From: Invoicing <invoice@example.at>\r\nReply-To: <a@example.at>\r\n\r\n",
	"From: <attacker@evil.example>, <invoice@example.at>\r\n\r\n",
	"From: g: attacker@evil.example; <invoice@example.at>\r\n\r\n",
	"From: \"Say \\\"hi, there\\\"\" <invoice@example.at>\r\n\r\n",
	"From: Sales (Vienna) <invoice@example.at>\r\n\r\n",
	"From: a@b.example\r\nFrom: c@d.example\r\n\r\n",
	"From: CEO\r\n <ceo@example.at>\r\n\r\n",
	"From: a\x00@example.at\r\n\r\n",
	"From: a@example.at\rBcc: x@evil.example\r\n\r\n",
	"From: a@example.at\nBcc: x@evil.example\r\n\r\n",
	"From: M\xc3\xbcller <mueller@example.at>\r\n\r\n",
	" orphan continuation\r\nSubject: x\r\n\r\n",
	"Subject: x\r\n\r\ntrailing body",
	"From: " + strings.Repeat("a", 600) + "@example.at\r\n\r\n",
}

func FuzzParseBlock(f *testing.F) {
	for _, s := range headerSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		blk, err := parseBlock(s)
		if err != nil {
			return
		}
		out := blk.String()
		again, err := parseBlock(out)
		if err != nil {
			t.Fatalf("String() of a parsed block does not parse: %v\n%q", err, out)
		}
		if got := again.String(); got != out {
			t.Fatalf("String() is not stable across a re-parse:\n first %q\nsecond %q", out, got)
		}
	})
}

// bareLineBreak reports a CR not followed by LF or an LF not preceded by CR.
func bareLineBreak(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\r':
			if i+1 == len(s) || s[i+1] != '\n' {
				return true
			}
		case '\n':
			if i == 0 || s[i-1] != '\r' {
				return true
			}
		}
	}
	return false
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func FuzzApply(f *testing.F) {
	rules := []*Rules{
		compile(f, config.Rewrite{
			Mode:         ModeForce,
			EnvelopeFrom: "relay@example.at",
			HeaderFrom:   "Printer Vienna <relay@example.at>",
		}),
		compile(f, config.Rewrite{Mode: ModeForce, EnvelopeFrom: "erp@example.at", HeaderFrom: HeaderFromKeep}),
	}
	for _, s := range headerSeeds {
		f.Add("scanner@printer.local", s)
		f.Add("", s)
	}
	f.Fuzz(func(t *testing.T, envelopeFrom, headers string) {
		// What the listener hands over: readStructuredLine refuses a bare CR
		// and splits on LF, so neither reaches Apply. A client's own
		// X-Original-From is excluded too, so that any one in the output is
		// the one Apply wrote.
		if bareLineBreak(headers) {
			return
		}
		if blk, err := parseBlock(headers); err == nil && blk.has("x-original-from") {
			return
		}
		for _, r := range rules {
			res, err := r.Apply(Input{EnvelopeFrom: envelopeFrom, Headers: headers})
			if err != nil {
				continue
			}
			if bareLineBreak(res.Headers) {
				t.Fatalf("output carries a bare CR or LF:\n%q", res.Headers)
			}
			out, err := parseBlock(res.Headers)
			if err != nil {
				t.Fatalf("output does not parse: %v\n%q", err, res.Headers)
			}
			if n := out.count("from"); n > 1 {
				t.Fatalf("output carries %d From fields:\n%q", n, res.Headers)
			}
			if v := out.value("x-original-from"); hasControl(v) {
				t.Fatalf("X-Original-From carries a control character: %q", v)
			}
		}
	})
}

func FuzzAddrOfMailbox(f *testing.F) {
	for _, s := range []string{
		"<invoice@example.at>",
		"invoice@example.at",
		"Invoicing <invoice@example.at>",
		"\"Invoicing, Vienna <AT>\" <invoice@example.at>",
		"<attacker@evil.example>, <invoice@example.at>",
		"g: attacker@evil.example; <invoice@example.at>",
		"Sales (Vienna) <invoice@example.at>",
		"\"Unterminated <invoice@example.at>",
		"\\\" <a@evil.example>, \"<invoice@example.at>",
		"a\x00@example.at",
		"<a@example.at\r\n>",
		"M\xc3\xbcller <mueller@example.at>",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a := addrOfMailbox(s)
		if a == "" {
			return
		}
		if !strings.Contains(s, a) {
			t.Fatalf("addrOfMailbox(%q) = %q, not part of its input", s, a)
		}
		// Apply refuses a From with a control character before asking this,
		// and it is under that precondition that none may come out.
		if checkHeaderValue(s) == nil && hasControl(a) {
			t.Fatalf("addrOfMailbox(%q) = %q carries a control character", s, a)
		}
	})
}
