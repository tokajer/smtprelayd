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
// The notes it returns alongside are listeners that accepted the relay from a
// source the configuration legitimately allowlists -- see probe. They are not
// failures, but they mean the default-deny path was not exercised, so the
// caller must show them rather than print an unqualified pass.
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
	addr := dialAddress(l.Address)
	d := &net.Dialer{Timeout: timeout}

	var conn net.Conn
	var err error
	if l.TLS == "implicit" {
		tc, terr := tlsConfig(cfg)
		if terr != nil {
			return "", terr
		}
		conn, err = tls.DialWithDialer(d, "tcp", addr, tc)
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	br := bufio.NewReader(conn)
	if _, err := expect(br, 220); err != nil {
		return "", err
	}
	if err := send(conn, "EHLO selftest.invalid"); err != nil {
		return "", err
	}
	if _, err := expect(br, 250); err != nil {
		return "", err
	}
	if err := send(conn, "MAIL FROM:<probe@selftest.invalid>"); err != nil {
		return "", err
	}
	code, line, err := expectAny(br)
	if err != nil {
		return "", err
	}
	if code >= 400 {
		return "", nil // rejected already, which is the desired outcome
	}
	if err := send(conn, "RCPT TO:<"+probeRecipient+">"); err != nil {
		return "", err
	}
	code, line, err = expectAny(br)
	if err != nil {
		return "", err
	}
	if code >= 400 {
		return "", nil
	}
	_ = send(conn, "RSET")
	return acceptedVerdict(match, conn, l, code, line)
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
