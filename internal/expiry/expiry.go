// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package expiry reports what the relay depends on that is going to stop
// working.
//
// Two things in this service expire on a date nobody is watching: the
// listener's own TLS certificate, and a Microsoft 365 client secret. Both
// were previously announced only in the log — the certificate not at all,
// the secret once at startup by delivery.warnSecretExpiry, which a service
// running for months never repeats. A log line nobody reads is not a
// warning, and both failures are total: an expired certificate refuses every
// TLS submission, an expired secret fails every delivery on that route.
//
// This package only answers "what expires and when". Deciding whether that
// is worth a mail, and sending one, is bounce.ExpiryWatcher's job -- keeping
// the two apart is what lets the dashboard and the metrics endpoint read
// these deadlines without dragging the whole mail-composition path in with
// them.
package expiry

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
)

// WarnWindow is how far ahead an expiry is announced, from
// expiry.warn_days. The default is thirty days, matching what
// delivery.warnSecretExpiry already logs at, because renewing either of these
// needs a person with rights they may not have today: a CA or an internal PKI
// for the certificate, a directory administrator for the client secret. Zero
// switches the warnings off.
func WarnWindow(cfg *config.Config) time.Duration {
	return time.Duration(cfg.Expiry.WarnDays) * 24 * time.Hour
}

// Item is one thing with a deadline.
type Item struct {
	// Key identifies the item across checks, so that a watcher can rate-limit
	// per item rather than per batch.
	Key     string
	What    string
	Detail  string
	Expires time.Time
}

// Items reports everything with a deadline that this service depends on,
// however far away it is, soonest first. The warning mail filters this by
// WarnWindow; the dashboard and the metrics endpoint show all of it, so that
// an operator can see a healthy expiry rather than only ever hearing about an
// unhealthy one.
//
// certErr is non-nil when tls.cert_file is configured but unreadable. That is
// not an Item: the listener would not have started on it, so it means the
// file changed under a running service, and the caller decides whether to log
// it or show it.
func Items(cfg *config.Config) (items []Item, certErr error) {
	if path := cfg.TLS.CertFile; path != "" {
		notAfter, err := certNotAfter(path)
		if err != nil {
			certErr = err
		} else {
			items = append(items, Item{
				Key:     "tls-certificate",
				What:    "the listener TLS certificate",
				Detail:  path,
				Expires: notAfter,
			})
		}
	}

	for _, r := range cfg.Routes {
		if r.Auth != "xoauth2" {
			continue
		}
		exp, ok := r.OAuth2.SecretExpiry()
		if !ok {
			continue // oauth2.secret_expires was not set; nothing to check
		}
		items = append(items, Item{
			Key:     "oauth2-secret:" + r.Name,
			What:    fmt.Sprintf("the Microsoft 365 client secret for route %q", r.Name),
			Detail:  "tenant " + r.OAuth2.TenantID,
			Expires: exp,
		})
	}
	// Soonest first, so the most urgent line is the one read first -- in the
	// mail and in the dashboard alike.
	sort.Slice(items, func(i, j int) bool { return items[i].Expires.Before(items[j].Expires) })
	return items, certErr
}

// DaysUntil is negative once t has passed. Truncating rather than rounding
// keeps "1 day left" from being printed for something lapsing in an hour.
func DaysUntil(t, now time.Time) int {
	return int(t.Sub(now).Hours() / 24)
}

// certNotAfter reads the leaf certificate's expiry. The file may hold a
// chain, and the leaf is the first block in it — the same one
// tls.LoadX509KeyPair presents to clients, so this reports on the
// certificate that is actually served.
func certNotAfter(path string) (time.Time, error) {
	raw, err := os.ReadFile(path) //#nosec G304 -- the path is tls.cert_file, an operator-supplied configuration value that the listener already opens
	if err != nil {
		return time.Time{}, err
	}
	for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, err
		}
		return c.NotAfter, nil
	}
	return time.Time{}, fmt.Errorf("no certificate found in %s", path)
}
