// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package smarthost delivers messages to an upstream SMTP smarthost.
package smarthost

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
)

// TempError marks a failure the sender should retry.
type TempError struct{ Err error }

func (e *TempError) Error() string { return e.Err.Error() }
func (e *TempError) Unwrap() error { return e.Err }

// PermError marks a failure that will not succeed on retry.
type PermError struct{ Err error }

func (e *PermError) Error() string { return e.Err.Error() }
func (e *PermError) Unwrap() error { return e.Err }

// AuthError marks a failure that is a property of the relay's own
// credentials — a rejected secret, an expired token, a rejected XOAUTH2
// challenge — rather than of the message. It is retried exactly like a
// TempError; the distinct type only lets a caller count it separately for
// the authentication-failure metric.
type AuthError struct{ Err error }

func (e *AuthError) Error() string { return e.Err.Error() }
func (e *AuthError) Unwrap() error { return e.Err }

func temp(format string, a ...any) error { return &TempError{Err: fmt.Errorf(format, a...)} }
func perm(format string, a ...any) error { return &PermError{Err: fmt.Errorf(format, a...)} }

// classify maps an SMTP reply onto a retry decision. Anything that is not an
// explicit 5xx is treated as temporary, because losing a message is worse
// than delivering it late.
func classify(err error) error {
	var te *textproto.Error
	if errors.As(err, &te) {
		if te.Code >= 500 && te.Code < 600 {
			return &PermError{Err: err}
		}
		return &TempError{Err: err}
	}
	return &TempError{Err: err}
}

// Message is one delivery attempt.
type Message struct {
	From string
	To   []string
	Data io.Reader
	// Helo is the name announced to the smarthost. Smarthosts authenticate on
	// credentials rather than on this value, but a sensible name keeps their
	// logs readable.
	Helo string
}

// Deliver sends a message through a configured route. Whenever a handshake
// happens at all, certificate verification is part of it: there is no code
// path here that negotiates TLS and then skips the check. A route may opt out
// of TLS entirely with tls = "none", which the loader restricts to routes
// that do not authenticate with XOAUTH2.
// tokens may be nil for routes that do not use XOAUTH2.
func Deliver(ctx context.Context, route config.Route, msg Message, timeout time.Duration, tokens TokenSource) error {
	var tlsConf *tls.Config
	if route.TLS != "none" {
		minTLS, err := config.ParseTLSVersion(route.MinTLS)
		if err != nil {
			return perm("route %s: %w", route.Name, err)
		}
		tlsConf = &tls.Config{
			ServerName: route.Host,
			MinVersion: minTLS,
		}
		if route.CAPin != "" {
			pin := strings.ToLower(strings.ReplaceAll(route.CAPin, ":", ""))
			tlsConf.VerifyConnection = pinVerifier(pin)
		}
	}

	addr := net.JoinHostPort(route.Host, strconv.Itoa(route.Port))
	dialer := &net.Dialer{Timeout: timeout}

	var conn net.Conn
	var err error
	if route.TLS == "implicit" {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConf}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return temp("connect %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	c, err := smtp.NewClient(conn, route.Host)
	if err != nil {
		conn.Close()
		return classify(err)
	}
	defer c.Close()

	if err := c.Hello(heloName(msg.Helo)); err != nil {
		return classify(err)
	}

	if route.TLS == "starttls" {
		ok, _ := c.Extension("STARTTLS")
		if !ok {
			// Never fall back to cleartext. Deferring gives an operator the
			// chance to fix the smarthost; sending in the clear would not.
			return temp("route %s: smarthost does not offer STARTTLS", route.Name)
		}
		if err := c.StartTLS(tlsConf); err != nil {
			return temp("route %s: STARTTLS failed: %w", route.Name, err)
		}
	}

	a, err := authFor(ctx, route, tokens)
	if err != nil {
		return err
	}
	if a != nil {
		// The loader already rejects this combination; repeating it here
		// keeps a hand-edited or future in-memory Route from putting
		// credentials on an unprotected connection.
		if route.TLS == "none" {
			return perm("route %s: refusing to authenticate over a cleartext connection", route.Name)
		}
		if err := c.Auth(a); err != nil {
			// An authentication failure is a property of the relay's
			// credentials, never of the message. Classifying the 535 as
			// permanent would empty the whole queue into spool/failed the
			// moment a client secret is rotated or a mailbox is disabled.
			if x, ok := a.(*xoauth2Auth); ok && x.challenge != "" {
				return &AuthError{Err: fmt.Errorf("route %s: XOAUTH2 rejected (%s): %w", route.Name, x.challenge, err)}
			}
			return &AuthError{Err: fmt.Errorf("route %s: authentication failed: %w", route.Name, err)}
		}
	}

	if err := c.Mail(msg.From); err != nil {
		return classify(err)
	}
	for _, rcpt := range msg.To {
		if err := c.Rcpt(rcpt); err != nil {
			return classify(err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return classify(err)
	}
	if _, err := io.Copy(w, msg.Data); err != nil {
		_ = w.Close()
		return temp("route %s: writing message: %w", route.Name, err)
	}
	if err := w.Close(); err != nil {
		return classify(err)
	}
	return c.Quit()
}

func authFor(ctx context.Context, route config.Route, tokens TokenSource) (smtp.Auth, error) {
	switch route.Auth {
	case "none", "":
		return nil, nil
	case "plain":
		return smtp.PlainAuth("", route.Credentials.Username,
			route.Credentials.Password.Value(), route.Host), nil
	case "login":
		return &loginAuth{
			username: route.Credentials.Username,
			password: route.Credentials.Password.Value(),
			host:     route.Host,
		}, nil
	case "xoauth2":
		if tokens == nil {
			return nil, perm("route %s: auth is xoauth2 but no token source was built", route.Name)
		}
		token, err := tokens.Token(ctx)
		if err != nil {
			// A missing token is an outage or a rotated secret, both of which
			// a later attempt can still succeed on.
			return nil, &AuthError{Err: fmt.Errorf("route %s: %w", route.Name, err)}
		}
		return &xoauth2Auth{user: route.OAuth2.Mailbox, token: token, host: route.Host}, nil
	default:
		return nil, perm("route %s: unsupported auth %q", route.Name, route.Auth)
	}
}

// loginAuth implements the non-standard but widely required LOGIN mechanism.
type loginAuth struct {
	username, password, host string
}

func (a *loginAuth) Start(s *smtp.ServerInfo) (string, []byte, error) {
	if !s.TLS {
		return "", nil, errors.New("smarthost: refusing LOGIN on an unencrypted connection")
	}
	if s.Name != a.host {
		return "", nil, errors.New("smarthost: server name does not match the configured host")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(strings.TrimSuffix(string(fromServer), ":"))) {
	case "username":
		return []byte(a.username), nil
	case "password":
		return []byte(a.password), nil
	}
	return nil, errors.New("smarthost: unexpected LOGIN challenge")
}

// pinVerifier restricts the accepted chain to one that contains a certificate
// matching the configured SHA-256 fingerprint. Chain verification itself has
// already happened by the time this runs; the pin only narrows it further.
//
// It is installed on VerifyConnection rather than VerifyPeerCertificate, for
// two reasons that both defeat the pin. VerifyPeerCertificate is handed the
// certificates the server sent, not the chain that was actually built from
// them, so a server holding any publicly trusted certificate for the host
// could satisfy the pin by appending the pinned certificate as an unused
// extra element. And it is skipped entirely on a resumed session, whereas
// VerifyConnection runs on every handshake and carries the verified chain
// restored from the session state.
func pinVerifier(pin string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		for _, chain := range cs.VerifiedChains {
			for _, cert := range chain {
				sum := sha256.Sum256(cert.Raw)
				if hex.EncodeToString(sum[:]) == pin {
					return nil
				}
			}
		}
		return errors.New("smarthost: no certificate in the verified chain matches ca_pin")
	}
}

func heloName(name string) string {
	if name == "" || strings.ContainsAny(name, " \r\n\x00") {
		return "localhost"
	}
	return name
}
