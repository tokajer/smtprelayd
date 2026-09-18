// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package selftest performs an active open-relay check against the running
// configuration. A passing unit test proves the matcher logic; only this
// proves the deployed configuration.
package selftest

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/listener"
)

const probeRecipient = "open-relay-probe@example.net"

// Run connects to every configured listener and attempts to relay to an
// external domain. Any listener that accepts the attempt is reported as a
// failure; the caller must treat a non-nil error as fatal.
//
// The notes it returns alongside are listeners whose relay policy this run
// did not actually establish anything about: one that accepted the relay from
// a source the configuration legitimately allowlists (see probe), and one
// that refused the probe for a reason other than relay policy (see
// refusalVerdict). They are not failures, but they mean the default-deny path
// was not exercised, so the caller must show them and must not print an
// unqualified pass.
func Run(cfg *config.Config, timeout time.Duration) ([]string, error) {
	// The relay's own matcher, not a second copy of it: this has to agree
	// with what the running listener would decide, and a reimplementation
	// here could pass while the real one denies, or the reverse.
	match, err := listener.NewMatcher(cfg.Clients)
	if err != nil {
		return nil, fmt.Errorf("selftest: %w", err)
	}
	var notes, failures []string
	for _, l := range cfg.Listeners {
		note, err := probe(cfg, match, l, timeout)
		if err != nil {
			failures = append(failures, fmt.Sprintf("listener %s (%s): %v", l.Name, l.Address, err))
		}
		if note != "" {
			notes = append(notes, note)
		}
	}
	if len(failures) > 0 {
		return notes, fmt.Errorf("open relay self-test failed:\n  - %s", strings.Join(failures, "\n  - "))
	}
	return notes, nil
}

// probe attempts one relay through one listener. It returns an error when the
// relay was accepted from a source that should not have been able to relay,
// and a note when it was accepted from a source the configuration allowlists.
//
// The distinction matters because the probe dials from this host, so it
// arrives on the listener as a connection from loopback. An operator who
// allowlists 127.0.0.1 -- an application relaying from the same machine, an
// ordinary deployment -- would otherwise have a correct configuration
// reported as an open relay by the very check that is meant to prove it is
// not one.
func probe(cfg *config.Config, match *listener.Matcher, l config.Listener, timeout time.Duration) (string, error) {
	conn, err := dialListener(cfg, l, timeout)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	br := bufio.NewReader(conn)
	if _, err := expect(br, 220); err != nil {
		return "", err
	}
	if err := greet(conn, br); err != nil {
		return "", err
	}

	// A starttls listener is probed over TLS rather than in the clear.
	// Without this, a listener with require_tls refuses at MAIL FROM with 530
	// before any relay policy is consulted, and the refusal below would read
	// that as a denial -- so hardening a listener silently turned the
	// open-relay check into a no-op on it. Measured before this existed: a
	// client with cidr 0.0.0.0/0, the open relay acceptedVerdict has a branch
	// for, produced a clean pass behind require_tls and a correct failure
	// without it.
	if l.TLS == "starttls" {
		conn, br, err = startTLS(cfg, conn, br, timeout)
		if err != nil {
			return "", err
		}
	}

	if err := send(conn, "MAIL FROM:<probe@selftest.invalid>"); err != nil {
		return "", err
	}
	code, line, err := expectAny(br)
	if err != nil {
		return "", err
	}
	if code >= 400 {
		return refusalVerdict(l, "MAIL FROM", code, line)
	}
	if err := send(conn, "RCPT TO:<"+probeRecipient+">"); err != nil {
		return "", err
	}
	code, line, err = expectAny(br)
	if err != nil {
		return "", err
	}
	if code >= 400 {
		return refusalVerdict(l, "RCPT TO", code, line)
	}
	_ = send(conn, "RSET")
	return acceptedVerdict(match, conn, l, code, line)
}

// dialListener opens the connection the listener expects: already encrypted
// for implicit TLS, cleartext otherwise, with STARTTLS negotiated afterwards.
func dialListener(cfg *config.Config, l config.Listener, timeout time.Duration) (net.Conn, error) {
	addr := dialAddress(l.Address)
	d := &net.Dialer{Timeout: timeout}
	if l.TLS != "implicit" {
		conn, err := d.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("connect: %w", err)
		}
		return conn, nil
	}
	tc, err := tlsConfig(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := tls.DialWithDialer(d, "tcp", addr, tc)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	return conn, nil
}

func greet(conn net.Conn, br *bufio.Reader) error {
	if err := send(conn, "EHLO selftest.invalid"); err != nil {
		return err
	}
	_, err := expect(br, 250)
	return err
}

// startTLS upgrades a cleartext session and greets again, which RFC 3207
// requires: everything learned before the handshake is discarded, because
// none of it was protected.
func startTLS(cfg *config.Config, conn net.Conn, br *bufio.Reader, timeout time.Duration) (net.Conn, *bufio.Reader, error) {
	tc, err := tlsConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := send(conn, "STARTTLS"); err != nil {
		return nil, nil, err
	}
	if _, err := expect(br, 220); err != nil {
		return nil, nil, fmt.Errorf("STARTTLS refused: %w", err)
	}
	// Anything already buffered was read before the handshake and is
	// therefore unauthenticated. Handing it to the TLS session is the classic
	// STARTTLS command-injection bug, so refuse rather than discard it: a
	// listener that pipelines past its own 220 is not one to keep probing.
	if n := br.Buffered(); n > 0 {
		return nil, nil, fmt.Errorf("listener sent %d bytes after its STARTTLS reply, before the handshake", n)
	}
	tlsConn := tls.Client(conn, tc)
	if err := tlsConn.Handshake(); err != nil {
		return nil, nil, fmt.Errorf("STARTTLS handshake: %w", err)
	}
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	fresh := bufio.NewReader(tlsConn)
	if err := greet(tlsConn, fresh); err != nil {
		return nil, nil, err
	}
	return tlsConn, fresh, nil
}

// refusalVerdict decides what a refusal means. Only a permanent refusal that
// the relay policy itself produced is the outcome this check exists to
// confirm. Two kinds are not, and both return a note rather than a silent
// pass, because the probe learned nothing and saying so is the difference
// between a proven configuration and a question that was never asked:
//
//   - 530, the listener demanding TLS the probe did not provide. A valid
//     configuration can no longer reach this -- validate refuses require_tls
//     on a tls = "none" listener, and probe now negotiates STARTTLS -- but
//     reading it as a denial is exactly what let a require_tls listener
//     report a clean pass while a catch-all client could relay through it, so
//     it stays named rather than folded back into the general case.
//   - any 4xx, which is temporary by definition: a rate limit or a busy
//     listener refuses an attempt it would accept a minute later.
func refusalVerdict(l config.Listener, stage string, code int, line string) (string, error) {
	switch {
	case code == 530:
		return fmt.Sprintf("listener %s refused the probe at %s with %d %s: it requires TLS the probe did not "+
			"negotiate, so its relay policy was never consulted and this run proves nothing about it.",
			l.Name, stage, code, line), nil
	case code < 500:
		return fmt.Sprintf("listener %s refused the probe at %s with %d %s: a temporary refusal is not a relay "+
			"decision, so this run proves nothing about it -- repeat the self-test once the listener is idle.",
			l.Name, stage, code, line), nil
	}
	return "", nil
}

// acceptedVerdict decides what an accepted relay means, given the source the
// probe actually reached the listener from.
func acceptedVerdict(match *listener.Matcher, conn net.Conn, l config.Listener, code int, line string) (string, error) {
	src, ok := localAddr(conn)
	if !ok {
		return "", fmt.Errorf("relay to %s was accepted with %d %s", probeRecipient, code, line)
	}
	cl, bits, matched := match.Match(src)
	if !matched {
		return "", fmt.Errorf("relay to %s from unmatched source %s was accepted with %d %s",
			probeRecipient, src, code, line)
	}
	if bits == 0 {
		// A client whose cidr covers every address is an open relay however
		// the match is reached, so an allowlist hit does not excuse it.
		return "", fmt.Errorf("relay to %s was accepted from %s, allowed by client %q whose cidr covers every address: that is an open relay",
			probeRecipient, src, cl.Name)
	}
	return fmt.Sprintf("listener %s accepted the relay from %s, which the configuration allowlists as client %q; "+
		"an allowlisted source is supposed to relay, so this is not an open relay. "+
		"The default-deny path was therefore not exercised -- to test it, run the probe from an address outside every client cidr.",
		l.Name, src, cl.Name), nil
}

// localAddr is the address the listener sees this probe arriving from.
func localAddr(conn net.Conn) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// tlsConfig replaces chain verification with an exact pin on the listener's
// own certificate. The probe must reach this service and no other, and the
// relay certificate is typically internal and not chain-verifiable from here.
func tlsConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.TLS.CertFile == "" {
		return nil, errors.New("implicit TLS listener without a configured certificate")
	}
	raw, err := os.ReadFile(cfg.TLS.CertFile)
	if err != nil {
		return nil, err
	}
	var want [][]byte
	for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			want = append(want, block.Bytes)
		}
	}
	if len(want) == 0 {
		return nil, fmt.Errorf("no certificate found in %s", cfg.TLS.CertFile)
	}
	//#nosec G123 -- see InsecureSkipVerify below: this dials the relay's own listener with a fresh Config and no session cache, so no session exists to resume around the pin
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //#nosec G402,G123 -- replaced by the exact pin in VerifyPeerCertificate below; this probe dials the relay's own listener with no session cache, so there is no resumption path around the pin
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, got := range rawCerts {
				for _, w := range want {
					if bytes.Equal(got, w) {
						return nil
					}
				}
			}
			return errors.New("listener presented an unexpected certificate")
		},
	}, nil
}

// dialAddress turns a wildcard bind address into something dialable.
func dialAddress(bind string) string {
	host, port, err := net.SplitHostPort(bind)
	if err != nil {
		return bind
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func send(conn net.Conn, line string) error {
	_, err := conn.Write([]byte(line + "\r\n"))
	return err
}

func expect(br *bufio.Reader, want int) (string, error) {
	code, line, err := expectAny(br)
	if err != nil {
		return "", err
	}
	if code != want {
		return "", fmt.Errorf("expected %d, got %d %s", want, code, line)
	}
	return line, nil
}

// expectAny consumes a possibly multi-line reply and returns its final code.
func expectAny(br *bufio.Reader) (int, string, error) {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return 0, "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 {
			return 0, "", fmt.Errorf("malformed reply %q", line)
		}
		if line[3] == '-' {
			continue
		}
		var code int
		if _, err := fmt.Sscanf(line[:3], "%d", &code); err != nil {
			return 0, "", fmt.Errorf("malformed reply %q", line)
		}
		return code, line[4:], nil
	}
}
