// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package selftest

import (
	"bufio"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/certgen"
	"github.com/tokajer/smtprelayd/internal/config"
)

// requireTLSRelay reproduces the two things that matter about a hardened
// listener: it offers STARTTLS, and it refuses MAIL FROM with 530 until the
// handshake has happened -- exactly what session.doMail does, and before any
// relay policy is consulted. Once TLS is up it accepts everything, which
// makes it an open relay for a client whose cidr covers the probe.
func requireTLSRelay(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				secure := false
				br := bufio.NewReader(conn)
				write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
				write("220 stub ESMTP")
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					switch verb := strings.ToUpper(strings.TrimRight(line, "\r\n")); {
					case strings.HasPrefix(verb, "EHLO"), strings.HasPrefix(verb, "HELO"):
						if secure {
							write("250 stub")
						} else {
							write("250-stub")
							write("250 STARTTLS")
						}
					case strings.HasPrefix(verb, "STARTTLS"):
						write("220 2.0.0 ready to start TLS")
						sc := tls.Server(conn, &tls.Config{
							Certificates: []tls.Certificate{cert},
							MinVersion:   tls.VersionTLS12,
						})
						if err := sc.Handshake(); err != nil {
							return
						}
						conn, secure = sc, true
						_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
						br = bufio.NewReader(conn)
						write = func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
					case strings.HasPrefix(verb, "MAIL"):
						if !secure {
							write("530 5.7.0 must issue a STARTTLS command first")
							continue
						}
						write("250 2.1.0 OK")
					case strings.HasPrefix(verb, "RCPT"):
						write("250 2.1.5 OK")
					case strings.HasPrefix(verb, "RSET"):
						write("250 ok")
					case strings.HasPrefix(verb, "QUIT"):
						write("221 bye")
						return
					default:
						write("250 ok")
					}
				}
			}(raw)
		}
	}()
	return ln.Addr().String()
}

// tlsCfgFor builds a configuration whose listener speaks STARTTLS, with a
// real certificate on disk for the probe to pin against.
func tlsCfgFor(t *testing.T, addr string, clientCIDR ...string) *config.Config {
	t.Helper()
	certPEM, keyPEM, err := certgen.Generate(certgen.Options{Hosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	c := &config.Config{
		Listeners: []config.Listener{{
			Name: "probe-target", Address: addr, TLS: "starttls", RequireTLS: true,
		}},
		TLS: config.TLS{CertFile: certFile, KeyFile: keyFile},
	}
	if len(clientCIDR) > 0 {
		c.Clients = []config.Client{{Name: "same-host-app", CIDR: clientCIDR}}
	}
	return c
}

func loadPair(t *testing.T, cfg *config.Config) tls.Certificate {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The regression this exists for. Before the probe negotiated STARTTLS, a
// listener with require_tls refused it at MAIL FROM with 530, which read as a
// relay denial -- so the identical catch-all client that
// TestAcceptedRelayFromCatchAllClientStillFails proves must be reported
// produced a completely clean pass, with no failure and no note. Hardening a
// listener turned its open-relay check into a no-op.
func TestCatchAllOpenRelayIsFoundThroughRequireTLS(t *testing.T) {
	// Build the config first so the stub serves the certificate the probe pins.
	cfg := tlsCfgFor(t, "127.0.0.1:0", "0.0.0.0/0")
	addr := requireTLSRelay(t, loadPair(t, cfg))
	cfg.Listeners[0].Address = addr

	_, err := Run(cfg, 5*time.Second)
	if err == nil {
		t.Fatal("a catch-all client behind require_tls is still an open relay and must fail")
	}
	if !strings.Contains(err.Error(), "open relay") {
		t.Fatalf("error should say it is an open relay, got %v", err)
	}
}

// The same listener with an allowlist that does not cover the probe: the
// relay decision is now actually reached, and it denies.
func TestRequireTLSListenerReachesTheRelayDecision(t *testing.T) {
	cfg := tlsCfgFor(t, "127.0.0.1:0", "10.0.0.0/8")
	addr := requireTLSRelay(t, loadPair(t, cfg))
	cfg.Listeners[0].Address = addr

	_, err := Run(cfg, 5*time.Second)
	// The stub accepts once TLS is up, and the probe arrives from loopback,
	// which 10.0.0.0/8 does not cover -- so this is the open-relay failure,
	// proving the probe got past the TLS gate to the policy behind it.
	if err == nil {
		t.Fatal("the probe did not reach the relay decision behind require_tls")
	}
	if !strings.Contains(err.Error(), "unmatched source") {
		t.Fatalf("error should name the unmatched source, got %v", err)
	}
}

// A refusal the relay policy did not produce must be a note, never a silent
// pass: 530 says the listener wanted TLS the probe did not provide.
func TestTLSRefusalIsANoteNotASilentPass(t *testing.T) {
	addr := stubRelay(t, "530 5.7.0 must issue a STARTTLS command first", "250 ok")
	notes, err := Run(cfgFor(addr, "0.0.0.0/0"), 2*time.Second)
	if err != nil {
		t.Fatalf("an unasked question is not a failure, got %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("want exactly one note, got %v", notes)
	}
	if !strings.Contains(notes[0], "proves nothing") {
		t.Errorf("note must say the run established nothing, got %q", notes[0])
	}
}

// A temporary refusal is not a relay decision either: the same attempt may be
// accepted once the rate limit window rolls over.
func TestTemporaryRefusalIsANoteNotASilentPass(t *testing.T) {
	addr := stubRelay(t, "451 4.7.0 rate limit exceeded, try again later", "250 ok")
	notes, err := Run(cfgFor(addr, "0.0.0.0/0"), 2*time.Second)
	if err != nil {
		t.Fatalf("a temporary refusal is not a failure, got %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("want exactly one note, got %v", notes)
	}
	if !strings.Contains(notes[0], "temporary refusal") {
		t.Errorf("note must say why it proves nothing, got %q", notes[0])
	}
}
