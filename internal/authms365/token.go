// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package authms365 acquires and caches Microsoft 365 OAuth2 access tokens
// using the client credentials flow described in docs/guides/MS365-AUTH.md.
package authms365

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
)

const (
	// authority is fixed rather than configurable. The client secret is sent
	// in the request body, so a mistyped or injected host would receive it.
	// The sovereign clouds are out of scope; adding them is a schema decision.
	authority = "login.microsoftonline.com"

	// refreshSkew renews early so that a token cannot expire between AUTH and
	// the end of DATA on a slow connection.
	refreshSkew = 5 * time.Minute

	// failCooldown throttles the token endpoint after a rejected request. A
	// rotated or expired secret would otherwise turn every queued message
	// into another request, which is how a tenant earns a hard block.
	failCooldown = 30 * time.Second

	requestTimeout   = 15 * time.Second
	maxResponseBytes = 1 << 20
)

// TokenSource caches one access token per route. The zero value is unusable;
// build it with New.
type TokenSource struct {
	clientID string
	secret   string
	scope    string

	// endpoint is derived from the tenant at construction time. Tests replace
	// it; it is not reachable from the configuration schema.
	endpoint string
	client   *http.Client

	mu         sync.Mutex
	token      string
	issued     time.Time
	expires    time.Time
	lastErr    error
	retryAfter time.Time
}

// Options are the resolved credentials for one route. The secret is passed as
// a plain string because it has already been dereferenced by the
// configuration loader; it is never read from a file or an environment
// variable here.
type Options struct {
	TenantID string
	ClientID string
	Secret   string
	Scope    string
}

// New validates the credentials and builds a token source for them.
func New(o Options) (*TokenSource, error) {
	if !config.ValidTenantID(o.TenantID) {
		return nil, fmt.Errorf("authms365: tenant_id %q is not a tenant GUID or domain name", o.TenantID)
	}
	if o.ClientID == "" {
		return nil, errors.New("authms365: client_id is empty")
	}
	if o.Secret == "" {
		return nil, errors.New("authms365: client_secret is empty")
	}
	scope := o.Scope
	if scope == "" {
		scope = config.DefaultScope
	}

	// url.URL escapes the path it is given; the tenant is additionally
	// constrained to a character set that cannot traverse or add a segment.
	u := url.URL{
		Scheme: "https",
		Host:   authority,
		Path:   "/" + o.TenantID + "/oauth2/v2.0/token",
	}

	return &TokenSource{
		clientID: o.ClientID,
		secret:   o.Secret,
		scope:    scope,
		endpoint: u.String(),
		client: &http.Client{
			Timeout: requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				// Following a redirect would repeat the POST body, and with
				// it the client secret, to whatever host the response names.
				return errors.New("authms365: refusing to follow a redirect from the token endpoint")
			},
			Transport: &http.Transport{
				Proxy:             nil,
				TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2: true,
			},
		},
	}, nil
}

// Token returns a cached token or acquires a new one. Callers are serialised,
// so a burst of delivery workers produces one request, not one per worker.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if s.token != "" && now.Before(s.expires.Add(-refreshSkew)) {
		return s.token, nil
	}
	if s.lastErr != nil && now.Before(s.retryAfter) {
		// A token still inside its lifetime is preferable to failing a
		// delivery while the cooldown runs.
		if s.token != "" && now.Before(s.expires) {
			return s.token, nil
		}
		return "", s.lastErr
	}

	token, expires, err := s.fetch(ctx)
	if err != nil {
		s.lastErr, s.retryAfter = err, now.Add(failCooldown)
		if s.token != "" && now.Before(s.expires) {
			return s.token, nil
		}
		return "", err
	}
	s.token, s.expires, s.lastErr = token, expires, nil
	s.issued = now
	return token, nil
}

// TokenAge reports how long the currently cached token has been held, and
// whether one is cached at all. It is read by the metrics endpoint only;
// the token value itself never leaves this package.
func (s *TokenSource) TokenAge() (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token == "" {
		return 0, false
	}
	return time.Since(s.issued), true
}

func (s *TokenSource) fetch(ctx context.Context) (string, time.Time, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {s.clientID},
		"client_secret": {s.secret},
		"scope":         {s.scope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("authms365: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		// url.Error carries the request URL but never the body, so the secret
		// stays out of the error and therefore out of the log.
		return "", time.Time{}, fmt.Errorf("authms365: token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("authms365: reading token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, responseError(resp.StatusCode, body)
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", time.Time{}, fmt.Errorf("authms365: token response is not valid JSON: %w", err)
	}
	if !strings.EqualFold(payload.TokenType, "Bearer") {
		return "", time.Time{}, fmt.Errorf("authms365: unexpected token type %q", payload.TokenType)
	}
	if err := checkToken(payload.AccessToken); err != nil {
		return "", time.Time{}, err
	}
	if payload.ExpiresIn <= 0 {
		return "", time.Time{}, errors.New("authms365: token response has no usable expires_in")
	}
	return payload.AccessToken, time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second), nil
}

// responseError turns the Entra ID error document into one log line. The raw
// body is not logged: it is long, it repeats the request, and it is the kind
// of blob that ends up pasted into a ticket.
func responseError(status int, body []byte) error {
	var e struct {
		Code        string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &e); err != nil || e.Code == "" {
		return fmt.Errorf("authms365: token endpoint returned HTTP %d", status)
	}
	return fmt.Errorf("authms365: token endpoint returned HTTP %d: %s: %s",
		status, e.Code, oneLine(e.Description, 200))
}

// checkToken rejects anything that could not survive the SASL payload. The
// token is concatenated with \x01 separators, so a token containing one would
// forge a field.
func checkToken(token string) error {
	if token == "" {
		return errors.New("authms365: token response contains no access token")
	}
	for _, r := range token {
		if r < 0x21 || r > 0x7e {
			return errors.New("authms365: access token contains a character that cannot appear in a SASL payload")
		}
	}
	return nil
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
