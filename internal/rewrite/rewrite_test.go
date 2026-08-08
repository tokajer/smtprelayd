// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package rewrite

import (
	"errors"
	"strings"
	"testing"

	"github.com/tokajer/smtprelayd/internal/config"
)

func compile(t *testing.T, r config.Rewrite) *Rules {
	t.Helper()
	rules, err := Compile(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return rules
}

const plainHeaders = "From: Scanner <scanner@printer.local>\r\n" +
	"To: ops@example.at\r\n" +
	"Subject: Scan\r\n" +
	"\r\n"

func TestForceRewritesEnvelopeAndHeader(t *testing.T) {
	r := compile(t, config.Rewrite{
		Mode:         ModeForce,
		EnvelopeFrom: "relay@example.at",
		HeaderFrom:   "Printer Vienna <relay@example.at>",
	})
	res, err := r.Apply(Input{EnvelopeFrom: "scanner@printer.local", Headers: plainHeaders})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Rewritten || res.EnvelopeFrom != "relay@example.at" {
		t.Fatalf("envelope %q rewritten=%v", res.EnvelopeFrom, res.Rewritten)
	}
	if res.OriginalFrom != "scanner@printer.local" {
		t.Errorf("original envelope sender %q was not recorded", res.OriginalFrom)
	}
	if !strings.Contains(res.Headers, "From: Printer Vienna <relay@example.at>\r\n") {
		t.Errorf("From was not replaced:\n%s", res.Headers)
	}
	if !strings.Contains(res.Headers, "X-Original-From: Scanner <scanner@printer.local>\r\n") {
		t.Errorf("X-Original-From missing:\n%s", res.Headers)
	}
	if !strings.Contains(res.Headers, "Reply-To: <scanner@printer.local>\r\n") {
		t.Errorf("Reply-To was not preserved:\n%s", res.Headers)
	}
	if !strings.HasSuffix(res.Headers, "\r\n\r\n") {
		t.Errorf("header block no longer ends in a blank line:\n%q", res.Headers)
	}
	if strings.Contains(res.Headers, "Subject: Scan\r\n") == false {
		t.Errorf("an untouched header was lost:\n%s", res.Headers)
	}
}

func TestIfUnauthorizedLeavesAnAllowedSenderAlone(t *testing.T) {
	r := compile(t, config.Rewrite{
		Mode:           ModeIfUnauthorized,
		AllowedSenders: []string{"*@example.at", "erp@erp.example"},
		EnvelopeFrom:   "erp@example.at",
	})
	for _, sender := range []string{"anna@example.at", "ANNA@EXAMPLE.AT", "erp@erp.example"} {
		res, err := r.Apply(Input{EnvelopeFrom: sender, Headers: plainHeaders})
		if err != nil {
			t.Fatal(err)
		}
		if res.Rewritten || res.Headers != plainHeaders || res.EnvelopeFrom != sender {
			t.Errorf("%s was rewritten although it is allowed", sender)
		}
	}
	res, err := r.Apply(Input{EnvelopeFrom: "stranger@elsewhere.example", Headers: plainHeaders})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Rewritten || res.EnvelopeFrom != "erp@example.at" {
		t.Error("an unauthorised sender was not rewritten")
	}
}

func TestKeepOnlySurvivesWhenAligned(t *testing.T) {
	r := compile(t, config.Rewrite{
		Mode:           ModeIfUnauthorized,
		AllowedSenders: []string{"*@example.at"},
		EnvelopeFrom:   "erp@example.at",
		HeaderFrom:     HeaderFromKeep,
	})

	aligned := "From: Invoicing <invoice@example.at>\r\n\r\n"
	res, err := r.Apply(Input{EnvelopeFrom: "erp@erp.local", Headers: aligned})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Rewritten || res.Headers != aligned {
		t.Errorf("an aligned From was not kept:\n%s", res.Headers)
	}
	if res.EnvelopeFrom != "erp@example.at" {
		t.Errorf("envelope %q, want the rewritten sender", res.EnvelopeFrom)
	}

	res, err = r.Apply(Input{EnvelopeFrom: "erp@erp.local", Headers: plainHeaders})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Headers, "From: <erp@example.at>\r\n") {
		t.Errorf("a misaligned From was kept, which would fail DMARC:\n%s", res.Headers)
	}
}

func TestExistingReplyToIsNotOverwritten(t *testing.T) {
	r := compile(t, config.Rewrite{Mode: ModeForce, EnvelopeFrom: "relay@example.at"})
	in := "From: <scanner@printer.local>\r\nReply-To: <helpdesk@example.at>\r\n\r\n"
	res, err := r.Apply(Input{EnvelopeFrom: "scanner@printer.local", Headers: in})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(res.Headers, "Reply-To:") != 1 ||
		!strings.Contains(res.Headers, "Reply-To: <helpdesk@example.at>") {
		t.Errorf("the client's Reply-To was not left alone:\n%s", res.Headers)
	}
}

func TestReplyToDropAndFixed(t *testing.T) {
	in := "From: <scanner@printer.local>\r\nReply-To: <helpdesk@example.at>\r\n\r\n"

	drop := compile(t, config.Rewrite{Mode: ModeForce, EnvelopeFrom: "relay@example.at", ReplyTo: "drop"})
	res, err := drop.Apply(Input{EnvelopeFrom: "scanner@printer.local", Headers: in})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Headers, "Reply-To:") {
		t.Errorf("Reply-To survived drop:\n%s", res.Headers)
	}

	fixed := compile(t, config.Rewrite{
		Mode: ModeForce, EnvelopeFrom: "relay@example.at", ReplyTo: "fixed:noreply@example.at",
	})
	res, err = fixed.Apply(Input{EnvelopeFrom: "scanner@printer.local", Headers: in})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(res.Headers, "Reply-To:") != 1 ||
		!strings.Contains(res.Headers, "Reply-To: <noreply@example.at>") {
		t.Errorf("fixed Reply-To was not applied:\n%s", res.Headers)
	}
}

func TestOffAndNullSenderAreUntouched(t *testing.T) {
	off := compile(t, config.Rewrite{Mode: ModeOff})
	res, err := off.Apply(Input{EnvelopeFrom: "scanner@printer.local", Headers: plainHeaders})
	if err != nil || res.Rewritten || res.Headers != plainHeaders {
		t.Errorf("mode off changed the message: %v %v", res.Rewritten, err)
	}

	// A null reverse path is a bounce. Giving it a sender is how a
	// notification loop starts.
	force := compile(t, config.Rewrite{Mode: ModeForce, EnvelopeFrom: "relay@example.at"})
	res, err = force.Apply(Input{EnvelopeFrom: "", Headers: plainHeaders})
	if err != nil || res.Rewritten || res.EnvelopeFrom != "" {
		t.Errorf("the null reverse path was rewritten: %q %v", res.EnvelopeFrom, err)
	}
}

func TestTwoFromHeadersAreRefused(t *testing.T) {
	r := compile(t, config.Rewrite{Mode: ModeForce, EnvelopeFrom: "relay@example.at"})
	in := "From: <a@printer.local>\r\nFrom: <b@printer.local>\r\n\r\n"
	if _, err := r.Apply(Input{EnvelopeFrom: "a@printer.local", Headers: in}); !errors.Is(err, ErrAmbiguousFrom) {
		t.Fatalf("got %v, want ErrAmbiguousFrom", err)
	}
}

func TestControlCharacterInFromIsRefused(t *testing.T) {
	r := compile(t, config.Rewrite{Mode: ModeForce, EnvelopeFrom: "relay@example.at"})
	in := "From: Scan\x01ner <scanner@printer.local>\r\n\r\n"
	if _, err := r.Apply(Input{EnvelopeFrom: "scanner@printer.local", Headers: in}); !errors.Is(err, ErrUnsafeHeader) {
		t.Fatalf("got %v, want ErrUnsafeHeader", err)
	}
}

func TestOverlongFromIsRefusedNotTruncated(t *testing.T) {
	r := compile(t, config.Rewrite{Mode: ModeForce, EnvelopeFrom: "relay@example.at"})
	in := "From: " + strings.Repeat("a", maxPreservedFrom+1) + " <scanner@printer.local>\r\n\r\n"
	if _, err := r.Apply(Input{EnvelopeFrom: "scanner@printer.local", Headers: in}); !errors.Is(err, ErrHeaderTooLong) {
		t.Fatalf("got %v, want ErrHeaderTooLong", err)
	}
}

func TestFoldedFromIsUnfoldedForPreservation(t *testing.T) {
	r := compile(t, config.Rewrite{Mode: ModeForce, EnvelopeFrom: "relay@example.at"})
	in := "From: Scanner\r\n\t<scanner@printer.local>\r\nSubject: x\r\n\r\n"
	res, err := r.Apply(Input{EnvelopeFrom: "scanner@printer.local", Headers: in})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Headers, "X-Original-From: Scanner <scanner@printer.local>\r\n") {
		t.Errorf("folded From was not unfolded into one line:\n%s", res.Headers)
	}
	if strings.Count(res.Headers, "From:") != 2 {
		t.Errorf("the folded continuation was not consumed with its header:\n%s", res.Headers)
	}
}

func TestCompileRefusesMisalignedOrUnsafeConfiguration(t *testing.T) {
	cases := map[string]config.Rewrite{
		"header_from in another domain": {
			Mode: ModeForce, EnvelopeFrom: "relay@example.at",
			HeaderFrom: "<relay@elsewhere.example>",
		},
		"display name with an angle bracket": {
			Mode: ModeForce, EnvelopeFrom: "relay@example.at",
			HeaderFrom: "Ops <x> <relay@example.at>",
		},
		"envelope_from is not an address": {
			Mode: ModeForce, EnvelopeFrom: "relay",
		},
		"if_unauthorized without an allowlist": {
			Mode: ModeIfUnauthorized, EnvelopeFrom: "relay@example.at",
		},
		"unknown reply_to": {
			Mode: ModeForce, EnvelopeFrom: "relay@example.at", ReplyTo: "sometimes",
		},
		"wildcard local part": {
			Mode: ModeIfUnauthorized, EnvelopeFrom: "relay@example.at",
			AllowedSenders: []string{"*@*"},
		},
	}
	for name, r := range cases {
		if _, err := Compile(r); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestDisplayNameIsQuotedWhenItMustBe(t *testing.T) {
	r := compile(t, config.Rewrite{
		Mode: ModeForce, EnvelopeFrom: "relay@example.at",
		HeaderFrom: "Dr. Ops <relay@example.at>",
	})
	res, err := r.Apply(Input{EnvelopeFrom: "scanner@printer.local", Headers: plainHeaders})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Headers, `From: "Dr. Ops" <relay@example.at>`) {
		t.Errorf("display name needing quotes was emitted bare:\n%s", res.Headers)
	}
}
