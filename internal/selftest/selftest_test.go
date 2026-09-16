// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package selftest

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
)

// stubRelay answers just enough SMTP for probe to reach a verdict. mailReply
// and rcptReply are the raw replies to MAIL FROM and RCPT TO, which is where
// a relay either refuses the probe or accepts it.
func stubRelay(t *testing.T, mailReply, rcptReply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(conn)
				write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
				write("220 stub ESMTP")
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					verb := strings.ToUpper(strings.TrimRight(line, "\r\n"))
					switch {
					case strings.HasPrefix(verb, "EHLO"), strings.HasPrefix(verb, "HELO"):
						write("250 stub")
					case strings.HasPrefix(verb, "MAIL"):
						write(mailReply)
					case strings.HasPrefix(verb, "RCPT"):
						write(rcptReply)
					case strings.HasPrefix(verb, "RSET"):
						write("250 ok")
					case strings.HasPrefix(verb, "QUIT"):
						write("221 bye")
						return
					default:
						write("250 ok")
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func cfgFor(addr string, clientCIDR ...string) *config.Config {
	c := &config.Config{
		Listeners: []config.Listener{{Name: "probe-target", Address: addr, TLS: "none"}},
	}
	if len(clientCIDR) > 0 {
		c.Clients = []config.Client{{Name: "same-host-app", CIDR: clientCIDR}}
	}
	return c
}

// A relay that refuses the probe is the whole point of the check, and must
// pass with nothing to report either way.
func TestRefusedRelayPassesSilently(t *testing.T) {
	addr := stubRelay(t, "250 ok", "554 5.7.1 relay access denied")
	notes, err := Run(cfgFor(addr), 2*time.Second)
	if err != nil {
		t.Fatalf("a refused relay must pass, got %v", err)
	}
	if len(notes) != 0 {
		t.Fatalf("a refused relay must produce no notes, got %v", notes)
	}
}

// Refusal at MAIL FROM, before a recipient is ever named, is the path the
// real listener takes for an unmatched source.
func TestRefusalAtMailFromPasses(t *testing.T) {
	addr := stubRelay(t, "550 5.7.1 not permitted to relay", "250 ok")
	notes, err := Run(cfgFor(addr), 2*time.Second)
	if err != nil {
		t.Fatalf("a refused relay must pass, got %v", err)
	}
	if len(notes) != 0 {
		t.Fatalf("got notes %v, want none", notes)
	}
}

// The failure this check exists to catch: the relay accepted, and the source
// it accepted from is not allowlisted anywhere.
func TestAcceptedRelayFromUnmatchedSourceFails(t *testing.T) {
	addr := stubRelay(t, "250 ok", "250 ok")
	_, err := Run(cfgFor(addr), 2*time.Second)
	if err == nil {
		t.Fatal("an accepted relay from an unmatched source must fail the self-test")
	}
	if !strings.Contains(err.Error(), "unmatched source") {
		t.Fatalf("error should name the unmatched source, got %v", err)
	}
}

// The false positive this fix is about: the probe dials from this host, so an
// operator who legitimately allowlists loopback had a correct configuration
// reported as an open relay.
func TestAcceptedRelayFromAllowlistedSourceIsANoteNotAFailure(t *testing.T) {
	addr := stubRelay(t, "250 ok", "250 ok")
	notes, err := Run(cfgFor(addr, "127.0.0.1/32"), 2*time.Second)
	if err != nil {
		t.Fatalf("an allowlisted source is supposed to relay, got failure %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("want exactly one note, got %v", notes)
	}
	// The note has to say the default-deny path went untested, or it reads
	// as an unqualified pass.
	if !strings.Contains(notes[0], "same-host-app") {
		t.Errorf("note should name the matched client, got %q", notes[0])
	}
	if !strings.Contains(notes[0], "not exercised") {
		t.Errorf("note should say the default-deny path was not exercised, got %q", notes[0])
	}
}

// An allowlist hit must not excuse a client that allows the whole internet:
// that is an open relay however the match was reached.
func TestAcceptedRelayFromCatchAllClientStillFails(t *testing.T) {
	addr := stubRelay(t, "250 ok", "250 ok")
	_, err := Run(cfgFor(addr, "0.0.0.0/0"), 2*time.Second)
	if err == nil {
		t.Fatal("a client whose cidr covers every address is an open relay and must fail")
	}
	if !strings.Contains(err.Error(), "open relay") {
		t.Fatalf("error should say it is an open relay, got %v", err)
	}
}
