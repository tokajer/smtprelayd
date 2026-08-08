// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package smarthost

import (
	"net/smtp"
	"strings"
	"testing"
)

func TestXOAUTH2Payload(t *testing.T) {
	got, err := xoauth2Payload("relay@example.at", "abc.def.ghi")
	if err != nil {
		t.Fatalf("xoauth2Payload: %v", err)
	}
	want := "user=relay@example.at\x01auth=Bearer abc.def.ghi\x01\x01"
	if string(got) != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}

func TestXOAUTH2PayloadRefusesForgedFields(t *testing.T) {
	cases := map[string][2]string{
		"separator in mailbox": {"relay\x01auth=Bearer stolen", "token"},
		"separator in token":   {"relay@example.at", "tok\x01en"},
		"newline in token":     {"relay@example.at", "tok\r\nen"},
		"empty mailbox":        {"", "token"},
		"empty token":          {"relay@example.at", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := xoauth2Payload(c[0], c[1]); err == nil {
				t.Fatal("payload was built from an unsafe value")
			}
		})
	}
}

func TestXOAUTH2RefusesCleartextAndWrongHost(t *testing.T) {
	a := &xoauth2Auth{user: "relay@example.at", token: "abc", host: "smtp.office365.com"}

	if _, _, err := a.Start(&smtp.ServerInfo{Name: "smtp.office365.com", TLS: false}); err == nil {
		t.Fatal("XOAUTH2 was offered on an unencrypted connection")
	}
	if _, _, err := a.Start(&smtp.ServerInfo{Name: "evil.example", TLS: true}); err == nil {
		t.Fatal("XOAUTH2 was offered to a server other than the configured host")
	}
	proto, payload, err := a.Start(&smtp.ServerInfo{Name: "smtp.office365.com", TLS: true})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if proto != "XOAUTH2" || len(payload) == 0 {
		t.Fatalf("Start returned %q with a %d byte payload", proto, len(payload))
	}
}

// A nil response on a continuation would end the AUTH loop in net/smtp without
// an error, which the client would read as a successful login.
func TestXOAUTH2ChallengeIsAnsweredNotAccepted(t *testing.T) {
	a := &xoauth2Auth{user: "relay@example.at", token: "abc", host: "smtp.office365.com"}
	resp, err := a.Next([]byte(`{"status":"401","schemes":"Bearer","scope":"https://outlook.office365.com/"}`), true)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if resp == nil {
		t.Fatal("a rejected token produced a nil response, which reads as success")
	}
	if len(resp) != 0 {
		t.Fatalf("response = %q, want empty", resp)
	}
	if !strings.Contains(a.challenge, "401") {
		t.Fatalf("challenge = %q, want the decoded status", a.challenge)
	}
}

func TestDecodeChallengeFallsBackToRawText(t *testing.T) {
	got := decodeChallenge([]byte("mailbox unavailable\r\nretry later"))
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("challenge %q still spans lines", got)
	}
}
