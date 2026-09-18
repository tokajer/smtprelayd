// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package smarthost

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
)

// scriptedServer speaks enough SMTP to carry one message to the point under
// test. dropAfterData makes it hang up the moment it has accepted the body,
// which is what Exchange does when it does not wait for QUIT.
type scriptedServer struct {
	dropAfterData bool
	sawAuth       chan string
}

func startScripted(t *testing.T, s *scriptedServer) (host string, port int) {
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
			go s.handle(conn)
		}
	}()
	h, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return h, n
}

func (s *scriptedServer) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	say := func(line string) { _, _ = io.WriteString(conn, line+"\r\n") }

	say("220 scripted ESMTP")
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			// One line, so net/smtp negotiates no extensions.
			say("250 scripted")
		case strings.HasPrefix(cmd, "AUTH"):
			if s.sawAuth != nil {
				select {
				case s.sawAuth <- strings.TrimSpace(line):
				default:
				}
			}
			say("535 5.7.8 authentication failed")
		case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
			say("250 2.1.0 ok")
		case strings.HasPrefix(cmd, "DATA"):
			say("354 end with <CRLF>.<CRLF>")
			for {
				l, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(l, "\r\n") == "." {
					break
				}
			}
			say("250 2.0.0 Ok: queued as SCRIPTED1")
			if s.dropAfterData {
				return
			}
		case strings.HasPrefix(cmd, "QUIT"):
			say("221 2.0.0 bye")
			return
		default:
			say("250 2.0.0 ok")
		}
	}
}

func deliverTo(t *testing.T, route config.Route, tokens TokenSource) error {
	t.Helper()
	return Deliver(context.Background(), route, Message{
		From: "device@example.at", To: []string{"ops@example.net"},
		Data: strings.NewReader("Subject: t\r\n\r\nbody\r\n"), Helo: "relay.test",
	}, 10*time.Second, tokens)
}

// A smarthost that answers the body with 250 owns the message from that
// moment. Reporting a later QUIT failure as a delivery failure leaves the
// copy queued, and the next attempt delivers it a second time -- which is
// reachable on every service stop, because the cancellation hook expires the
// connection deadline and can land in exactly this gap.
func TestDeliverTreatsAQuitFailureAfterAcceptanceAsDelivered(t *testing.T) {
	host, port := startScripted(t, &scriptedServer{dropAfterData: true})
	route := config.Route{Name: "drop", Host: host, Port: port, TLS: "none", Auth: "none"}

	err := deliverTo(t, route, nil)

	var qe *QuitError
	if !errors.As(err, &qe) {
		t.Fatalf("Deliver returned %T (%v), want a *QuitError: the message was accepted", err, err)
	}
	// The distinction that matters to the caller: not retryable.
	var te *TempError
	var pe *PermError
	if errors.As(err, &te) || errors.As(err, &pe) {
		t.Error("a QuitError must not also classify as temporary or permanent; it would be retried")
	}
}

// The happy path still reports plain success, so the branch above cannot be
// reached by a session that closed cleanly.
func TestDeliverReturnsNilWhenTheSessionClosesCleanly(t *testing.T) {
	host, port := startScripted(t, &scriptedServer{})
	route := config.Route{Name: "clean", Host: host, Port: port, TLS: "none", Auth: "none"}

	if err := deliverTo(t, route, nil); err != nil {
		t.Fatalf("Deliver returned %v against a server that answered every command", err)
	}
}

// Credentials never go onto an unprotected connection. config.Validate refuses
// the combination at load time and every mechanism refuses it again from
// inside, so this guard only ever fires for a Route that did not come through
// the loader -- which is precisely why nothing else holds it in place.
func TestDeliverRefusesToAuthenticateOverCleartext(t *testing.T) {
	saw := make(chan string, 1)
	host, port := startScripted(t, &scriptedServer{sawAuth: saw})
	route := config.Route{
		Name: "cleartext", Host: host, Port: port, TLS: "none", Auth: "plain",
		Credentials: config.Credentials{Username: "u"},
	}

	err := deliverTo(t, route, nil)

	var pe *PermError
	if !errors.As(err, &pe) {
		t.Fatalf("Deliver returned %T (%v), want a *PermError", err, err)
	}
	if !strings.Contains(err.Error(), "cleartext") {
		t.Errorf("error %q does not say why it refused", err)
	}
	select {
	case cmd := <-saw:
		t.Errorf("an AUTH command reached the wire on a cleartext route: %q", cmd)
	default:
	}
}

// authFor decides which credential goes onto the wire and was executed by
// nothing at all. Every branch is asserted on the concrete type it must
// produce, because the failure mode of a wrong one is a secret sent by the
// wrong mechanism rather than a compile error.
// A Secret's value is populated only by config.Load's resolve step and cannot
// be set from outside that package, so every Password here reads back empty
// while Username does not. That asymmetry is what makes the field assertions
// below worth making: a mechanism handed the username where the password
// belongs fails them.
func TestAuthForSelectsTheMechanism(t *testing.T) {
	creds := config.Credentials{Username: "u"}
	oauth := config.OAuth2{Mailbox: "relay@example.at"}

	tests := []struct {
		name   string
		route  config.Route
		tokens TokenSource
		want   interface{}
	}{
		{name: "none", route: config.Route{Auth: "none"}, want: nil},
		{name: "empty means none", route: config.Route{Auth: ""}, want: nil},
		{name: "plain", route: config.Route{Auth: "plain", Host: "h", Credentials: creds}, want: "plain"},
		{name: "login", route: config.Route{Auth: "login", Host: "h", Credentials: creds}, want: &loginAuth{}},
		{
			name:   "xoauth2",
			route:  config.Route{Auth: "xoauth2", Host: "h", OAuth2: oauth},
			tokens: staticToken("tok"),
			want:   &xoauth2Auth{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := authFor(context.Background(), tc.route, tc.tokens)
			if err != nil {
				t.Fatalf("authFor: %v", err)
			}
			switch want := tc.want.(type) {
			case nil:
				if a != nil {
					t.Fatalf("got %T, want no authentication at all", a)
				}
			case string: // smtp.PlainAuth is unexported, so only non-nil is assertable
				if a == nil {
					t.Fatalf("got nil, want the %s mechanism", want)
				}
				if _, ok := a.(*loginAuth); ok {
					t.Fatal("plain produced the LOGIN mechanism")
				}
				if _, ok := a.(*xoauth2Auth); ok {
					t.Fatal("plain produced the XOAUTH2 mechanism")
				}
			case *loginAuth:
				got, ok := a.(*loginAuth)
				if !ok {
					t.Fatalf("got %T, want *loginAuth", a)
				}
				if got.username != "u" || got.host != "h" {
					t.Errorf("credentials did not reach the mechanism: %+v", got)
				}
				if got.password != tc.route.Credentials.Password.Value() {
					t.Error("the LOGIN mechanism was handed something other than the password")
				}
			case *xoauth2Auth:
				got, ok := a.(*xoauth2Auth)
				if !ok {
					t.Fatalf("got %T, want *xoauth2Auth", a)
				}
				if got.token != "tok" || got.user != "relay@example.at" {
					t.Errorf("token or mailbox did not reach the mechanism: %+v", got)
				}
			}
		})
	}
}

// The two ways authFor refuses. Both are permanent: neither a missing token
// source nor an unknown mechanism is fixed by trying again.
func TestAuthForRefusesWhatItCannotBuild(t *testing.T) {
	t.Run("xoauth2 without a token source", func(t *testing.T) {
		_, err := authFor(context.Background(), config.Route{Name: "r", Auth: "xoauth2"}, nil)
		var pe *PermError
		if !errors.As(err, &pe) {
			t.Fatalf("got %T (%v), want a *PermError", err, err)
		}
	})

	t.Run("unsupported mechanism", func(t *testing.T) {
		_, err := authFor(context.Background(), config.Route{Name: "r", Auth: "cram-md5"}, nil)
		var pe *PermError
		if !errors.As(err, &pe) {
			t.Fatalf("got %T (%v), want a *PermError", err, err)
		}
	})

	// A token the source cannot produce is an outage or a rotated secret, so
	// it must be an AuthError and stay retryable rather than fail the message.
	t.Run("token source failing", func(t *testing.T) {
		_, err := authFor(context.Background(),
			config.Route{Name: "r", Auth: "xoauth2"}, failingToken{})
		var ae *AuthError
		if !errors.As(err, &ae) {
			t.Fatalf("got %T (%v), want an *AuthError", err, err)
		}
	})
}

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

type failingToken struct{}

func (failingToken) Token(context.Context) (string, error) {
	return "", errors.New("tenant unreachable")
}
