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
	"os"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
)

const probeRecipient = "open-relay-probe@example.net"

// Run connects to every configured listener and attempts to relay to an
// external domain. Any listener that accepts the attempt is reported as a
// failure; the caller must treat a non-nil error as fatal.
func Run(cfg *config.Config, timeout time.Duration) error {
	var failures []string
	for _, l := range cfg.Listeners {
		if err := probe(cfg, l, timeout); err != nil {
			failures = append(failures, fmt.Sprintf("listener %s (%s): %v", l.Name, l.Address, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("open relay self-test failed:\n  - %s", strings.Join(failures, "\n  - "))
	}
	return nil
}

func probe(cfg *config.Config, l config.Listener, timeout time.Duration) error {
	addr := dialAddress(l.Address)
	d := &net.Dialer{Timeout: timeout}

	var conn net.Conn
	var err error
	if l.TLS == "implicit" {
		tc, terr := tlsConfig(cfg)
		if terr != nil {
			return terr
		}
		conn, err = tls.DialWithDialer(d, "tcp", addr, tc)
	} else {
		conn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	br := bufio.NewReader(conn)
	if _, err := expect(br, 220); err != nil {
		return err
	}
	if err := send(conn, "EHLO selftest.invalid"); err != nil {
		return err
	}
	if _, err := expect(br, 250); err != nil {
		return err
	}
	if err := send(conn, "MAIL FROM:<probe@selftest.invalid>"); err != nil {
		return err
	}
	code, line, err := expectAny(br)
	if err != nil {
		return err
	}
	if code >= 400 {
		return nil // rejected already, which is the desired outcome
	}
	if err := send(conn, "RCPT TO:<"+probeRecipient+">"); err != nil {
		return err
	}
	code, line, err = expectAny(br)
	if err != nil {
		return err
	}
	if code >= 400 {
		return nil
	}
	_ = send(conn, "RSET")
	return fmt.Errorf("relay to %s was accepted with %d %s", probeRecipient, code, line)
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
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // replaced by the exact pin below
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
