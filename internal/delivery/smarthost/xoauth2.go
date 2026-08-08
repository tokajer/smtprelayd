// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package smarthost

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/smtp"
	"strings"
)

// TokenSource yields a bearer token for one route. It is satisfied by
// authms365.TokenSource; keeping it an interface leaves this package free of
// any knowledge of how tokens are acquired or cached.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// xoauth2Auth implements the XOAUTH2 mechanism that Microsoft 365 requires for
// unattended SMTP submission. The token is resolved before the connection is
// opened, so this type never performs I/O of its own.
type xoauth2Auth struct {
	user  string
	token string
	host  string

	// challenge holds the decoded server error from the failure path, so that
	// the caller can log something more useful than "535 5.7.3".
	challenge string
}

func (a *xoauth2Auth) Start(s *smtp.ServerInfo) (string, []byte, error) {
	if !s.TLS {
		return "", nil, errors.New("smarthost: refusing XOAUTH2 on an unencrypted connection")
	}
	if s.Name != a.host {
		return "", nil, errors.New("smarthost: server name does not match the configured host")
	}
	payload, err := xoauth2Payload(a.user, a.token)
	if err != nil {
		return "", nil, err
	}
	return "XOAUTH2", payload, nil
}

// Next handles the failure path only. A rejected token is answered with a 334
// continuation carrying a base64 JSON error, and the mechanism requires an
// empty client response before the server sends its final 5xx. Returning a nil
// response here would end the AUTH loop in net/smtp without an error, which
// would be indistinguishable from a successful authentication.
func (a *xoauth2Auth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.challenge = decodeChallenge(fromServer)
	return []byte{}, nil
}

// xoauth2Payload builds the SASL initial response. Both fields are validated
// because they are joined by \x01: a value containing one would forge a field.
func xoauth2Payload(user, token string) ([]byte, error) {
	if err := checkSASLField(user, "mailbox"); err != nil {
		return nil, err
	}
	if err := checkSASLField(token, "access token"); err != nil {
		return nil, err
	}
	return []byte("user=" + user + "\x01auth=Bearer " + token + "\x01\x01"), nil
}

func checkSASLField(s, what string) error {
	if s == "" {
		return fmt.Errorf("smarthost: empty %s for XOAUTH2", what)
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return fmt.Errorf("smarthost: %s contains a character that cannot appear in a SASL payload", what)
		}
	}
	return nil
}

// decodeChallenge turns the continuation into one log line. net/smtp has
// already base64-decoded it, but a second layer is tolerated because not every
// implementation agrees on that point.
func decodeChallenge(b []byte) string {
	s := strings.TrimSpace(string(b))
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && json.Valid(raw) {
		s = string(raw)
	}
	var e struct {
		Status  string `json:"status"`
		Schemes string `json:"schemes"`
		Scope   string `json:"scope"`
	}
	if err := json.Unmarshal([]byte(s), &e); err != nil || e.Status == "" {
		return oneLine(s, 200)
	}
	return fmt.Sprintf("status %s, schemes %q, scope %q", e.Status, e.Schemes, e.Scope)
}

func oneLine(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > max {
		return string(r[:max]) + "..."
	}
	return s
}
