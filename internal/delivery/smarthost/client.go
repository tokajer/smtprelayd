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

// QuitError reports that the smarthost accepted the message -- it answered
// the body with 250, so the message is its responsibility from that moment --
// but the session could not be closed cleanly afterwards. The delivery
// succeeded. A caller must treat this as success and must not retry, because
// retrying delivers the message a second time; it is a distinct type only so
// that the caller can say so in the log.
type QuitError struct{ Err error }

func (e *QuitError) Error() string { return e.Err.Error() }
func (e *QuitError) Unwrap() error { return e.Err }

// Rejection is one recipient the smarthost refused permanently, with the
// reply it gave. The reply is kept whole because it is what names the address
// and the reason, and it is what the operator needs to act on.
type Rejection struct {
	Recipient string
	Err       error
}

// String is the one rendering of a refusal in this tree. Both the error text
// and the copy the delivery manager records reuse it, so the two cannot drift
// into describing the same refusal differently.
func (r Rejection) String() string {
	return fmt.Sprintf("%s (%v)", r.Recipient, r.Err)
}

// PartialError reports that the message was delivered, but not to every
// recipient: the smarthost permanently refused the ones listed here and no
// retry will change that.
//
// The delivery succeeded for everyone else, so a caller must treat this as
// success. Retrying would deliver the message a second time to the recipients
// who did accept it -- the same rule QuitError carries, for the same reason.
// What it must not do is treat it as an ordinary success and say nothing:
// the refusals are how an operator learns which address to fix.
type PartialError struct {
	Route    string
	Rejected []Rejection
}

func (e *PartialError) Error() string {
	return fmt.Sprintf("route %s: delivered, but %d recipient(s) were refused: %s",
		e.Route, len(e.Rejected), describeRejections(e.Rejected))
}

// describeRejections renders the refusals as one line for a log field or an
// error string.
func describeRejections(rejected []Rejection) string {
	parts := make([]string, 0, len(rejected))
	for _, r := range rejected {
		parts = append(parts, r.String())
	}
	return strings.Join(parts, "; ")
}

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

// connectTimeout bounds establishing the connection -- the TCP handshake, and
// the TLS handshake too on an implicit-TLS route. A smarthost that is reachable
// at all answers far inside this; one that does not is not going to.
const connectTimeout = 30 * time.Second

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
	// The dial gets a bound of its own rather than the whole attempt budget.
	// timeout is limits.delivery_timeout_sec, 600s by default, because it has
	// to carry limits.max_message_mb at a pessimistic rate -- but a host that
	// drops packets, which is what an egress rule usually produces, would
	// otherwise spend all ten minutes of it here, on every attempt, having
	// sent nothing. conn.SetDeadline below still holds the full budget over
	// the rest of the session.
	dialer := &net.Dialer{Timeout: min(connectTimeout, timeout)}

	var conn net.Conn
	var err error
	if route.TLS == config.TLSImplicit {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConf}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return temp("connect %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// net/smtp takes no context, so everything after the dial -- the
	// handshake, SASL, and the whole DATA transfer -- would otherwise run to
	// the deadline above regardless of a shutdown. Expiring the deadline on
	// cancellation aborts whichever read or write is in flight at once. The
	// resulting error is a timeout, which classify treats as temporary, so
	// the message stays queued for the next start rather than being failed.
	//
	// Without this a service stop waits for the in-flight attempt: tolerable
	// under systemd's 90s default, not under the Windows SCM's five seconds,
	// where the service is reported as not responding and killed.
	stopOnCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopOnCancel()

	c, err := smtp.NewClient(conn, route.Host)
	if err != nil {
		conn.Close()
		return classify(err)
	}
	defer c.Close()

	if err := c.Hello(heloName(msg.Helo)); err != nil {
		return classify(err)
	}

	if route.TLS == config.TLSStartTLS {
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
	rejected, err := offerRecipients(c, route, msg.To)
	if err != nil {
		return err
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
	// A successful Close means the smarthost answered the body with 250 and
	// now owns the message. Nothing that happens to the session afterwards
	// changes that, so a failing QUIT must not be reported as a delivery
	// failure: the caller would leave the copy queued and the next attempt
	// would deliver it a second time. Three ordinary things reach this point
	// -- Exchange closing the connection after its 250 without waiting for
	// QUIT, the delivery deadline expiring in this gap on a large message,
	// and a service stop firing the cancellation armed above.
	//
	// This is the mirror of the rule the listener already applies on the way
	// in, where commitCopies withdraws partial copies rather than let a
	// client's retry duplicate them.
	quitErr := c.Quit()
	// A partial delivery outranks a failed goodbye: both mean "delivered,
	// do not retry", and the rejected addresses are the half an operator has
	// to act on. The QUIT failure is dropped in that case rather than
	// wrapped, because nothing downstream would do anything different with it.
	if len(rejected) > 0 {
		return &PartialError{Route: route.Name, Rejected: rejected}
	}
	if quitErr != nil {
		return &QuitError{Err: quitErr}
	}
	return nil
}

// offerRecipients issues one RCPT per recipient and decides what a refusal
// means for the message as a whole.
//
// A permanently refused recipient is that recipient's problem, not the
// message's: a mailbox that no longer exists must not stop the message
// reaching everyone else on a distribution list, which is what returning at
// the first refusal used to do -- measured, with a three-recipient message
// permanently bounced after its middle recipient was refused, while the other
// two had already been accepted with 250 in that same session.
//
// A *temporarily* refused recipient is different, and deliberately still ends
// the whole attempt before anything is sent. The message has to be retried
// for that recipient, and it cannot be retried for one recipient without
// being delivered a second time to the others, because a queued message is
// one envelope and not one per address. Deferring everything costs a delay;
// the alternative costs a duplicate, and duplicates are the thing this file
// spends most of its rules avoiding.
func offerRecipients(c *smtp.Client, route config.Route, to []string) ([]Rejection, error) {
	var rejected []Rejection
	accepted := 0
	for _, rcpt := range to {
		err := c.Rcpt(rcpt)
		switch {
		case err == nil:
			accepted++
		case isPermanentReply(err):
			rejected = append(rejected, Rejection{Recipient: rcpt, Err: err})
		default:
			return nil, classify(err)
		}
	}
	if accepted == 0 {
		// Nobody is left to send to, and no retry changes that. Reported as
		// one permanent failure so the message is moved aside exactly as it
		// was before this distinction existed.
		return nil, &PermError{Err: fmt.Errorf("route %s: every recipient was refused: %s",
			route.Name, describeRejections(rejected))}
	}
	return rejected, nil
}

// isPermanentReply reports whether a reply will never succeed on retry. It
// asks classify rather than reading the code itself, so there is one
// definition of permanent in this package.
func isPermanentReply(err error) bool {
	var pe *PermError
	return errors.As(classify(err), &pe)
}

func authFor(ctx context.Context, route config.Route, tokens TokenSource) (smtp.Auth, error) {
	switch route.Auth {
	case "none", "":
		return nil, nil
	case config.AuthPlain:
		return smtp.PlainAuth("", route.Credentials.Username,
			route.Credentials.Password.Value(), route.Host), nil
	case config.AuthLogin:
		return &loginAuth{
			username: route.Credentials.Username,
			password: route.Credentials.Password.Value(),
			host:     route.Host,
		}, nil
	case config.AuthXOAUTH2:
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
