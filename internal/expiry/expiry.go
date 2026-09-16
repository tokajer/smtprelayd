// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package expiry mails the operator before something the relay depends on
// stops working.
//
// Two things in this service expire on a date nobody is watching: the
// listener's own TLS certificate, and a Microsoft 365 client secret. Both
// were previously announced only in the log — the certificate not at all,
// the secret once at startup by delivery.warnSecretExpiry, which a service
// running for months never repeats. A log line nobody reads is not a
// warning, and both failures are total: an expired certificate refuses every
// TLS submission, an expired secret fails every delivery on that route.
//
// The notification goes through bounce.Notifier, so it reaches the same
// bounce.notify contacts over the same bounce.notify_route as a delivery
// failure digest, and needs no contact details of its own.
package expiry

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/bounce"
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

const (
	// resendInterval bounds how often the same item is mailed about. Once a
	// day is often enough that an operator cannot miss the window and rare
	// enough that the warning does not become noise they filter away.
	resendInterval = 24 * time.Hour

	// checkInterval is how often the watcher looks. The work is one file
	// read and a date comparison, so this is cheap; it is not shorter
	// because nothing here changes on a scale of minutes.
	checkInterval = time.Hour

	// source names this watcher to bounce.Notifier, which groups by it and
	// looks it up against client names when resolving recipients. A client
	// named this would capture these notifications into its own
	// bounce.notify override; nothing forbids that name, it is simply not
	// one a client is plausibly called.
	source = "expiry-watch"
)

// Item is one thing with a deadline.
type Item struct {
	// Key identifies the item across checks so that resendInterval applies
	// per item rather than to the batch.
	Key     string
	What    string
	Detail  string
	Expires time.Time
}

// Watcher periodically reports what is about to expire. It holds no state
// that must survive a restart: a restart re-checks immediately and mails
// again if anything is inside the window, which is the safe direction to err
// in for a warning.
type Watcher struct {
	cfg      *config.Config
	notifier *bounce.Notifier
	log      *slog.Logger

	// lastSent is read and written only from Run's own goroutine, or
	// directly by a test.
	lastSent map[string]time.Time
}

// New builds a watcher. It does nothing until Run is started.
func New(cfg *config.Config, n *bounce.Notifier, log *slog.Logger) *Watcher {
	return &Watcher{
		cfg: cfg, notifier: n,
		log:      log.With("component", "expiry"),
		lastSent: map[string]time.Time{},
	}
}

// Run checks immediately and then every checkInterval until ctx is
// cancelled. The immediate check matters: an operator restarting a service
// whose certificate expires next week should hear about it now, not in an
// hour.
func (w *Watcher) Run(ctx context.Context) {
	if WarnWindow(w.cfg) <= 0 {
		w.log.Info("expiry.warn_days is 0, expiry warnings are disabled")
		return
	}
	if len(w.cfg.Bounce.Notify) == 0 {
		// Nowhere to send. The startup log still carries what collect would
		// have found, so this is not silent, and Notify would return without
		// sending anyway.
		w.log.Debug("no bounce.notify configured, expiry warnings will not be mailed")
	}
	w.check(time.Now())
	t := time.NewTicker(checkInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.check(time.Now())
		}
	}
}

// check mails about everything inside the warning window that has not been
// mailed about recently. Items are batched into one message: an operator
// with a certificate and two secrets all expiring in the same month wants
// one mail, not three.
func (w *Watcher) check(now time.Time) {
	due := []Item{}
	for _, it := range w.collect(now) {
		if last, ok := w.lastSent[it.Key]; ok && now.Sub(last) < resendInterval {
			continue
		}
		due = append(due, it)
	}
	if len(due) == 0 {
		return
	}

	subject, body := compose(due, now, w.cfg.Service.Hostname, w.cfg.Expiry.WarnDays)
	if err := w.notifier.Notify(source, subject, body, now); err != nil {
		// Not marked as sent, so the next check tries again.
		w.log.Error("sending expiry warning failed", "error", err)
		return
	}
	for _, it := range due {
		w.lastSent[it.Key] = now
		w.log.Warn("expiry warning sent", "item", it.What, "expires", it.Expires.Format(time.RFC3339))
	}
}

// Items reports everything with a deadline that this service depends on,
// however far away it is, soonest first. The warning mail filters this by
// WarnBefore; the dashboard shows all of it, so that an operator can see a
// healthy expiry rather than only ever hearing about an unhealthy one.
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

// collect returns everything expiring within WarnBefore, already expired
// included: an expiry that has passed is the case an operator most needs
// told about, so it is reported rather than dropped for being out of range.
func (w *Watcher) collect(now time.Time) []Item {
	all, certErr := Items(w.cfg)
	if certErr != nil {
		// Worth a log line, not a mail: see Items.
		w.log.Warn("cannot read the TLS certificate to check its expiry",
			"file", w.cfg.TLS.CertFile, "error", certErr)
	}
	window := WarnWindow(w.cfg)
	if window <= 0 {
		return nil // warnings switched off
	}
	deadline := now.Add(window)
	var due []Item
	for _, it := range all {
		if it.Expires.Before(deadline) {
			due = append(due, it)
		}
	}
	return due
}

// compose renders the message. It says what breaks when each item lapses,
// because the recipient of this mail is not necessarily the person who
// configured the relay.
func compose(due []Item, now time.Time, hostname string, windowDays int) (subject, body string) {
	expired := 0
	for _, it := range due {
		if !it.Expires.After(now) {
			expired++
		}
	}
	switch {
	case expired > 0:
		subject = fmt.Sprintf("[smtprelayd] ACTION REQUIRED: %d item(s) expired on %s", expired, hostname)
	case len(due) == 1:
		subject = fmt.Sprintf("[smtprelayd] %s expires in %d day(s)", due[0].What, DaysUntil(due[0].Expires, now))
	default:
		subject = fmt.Sprintf("[smtprelayd] %d item(s) expire within %d days on %s",
			len(due), windowDays, hostname)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "smtprelayd on %s is reporting that the following will stop working:\r\n", hostname)
	for _, it := range due {
		days := DaysUntil(it.Expires, now)
		b.WriteString("\r\n")
		fmt.Fprintf(&b, "  %s\r\n", it.What)
		fmt.Fprintf(&b, "    %s\r\n", it.Detail)
		fmt.Fprintf(&b, "    expires: %s\r\n", it.Expires.Format(time.RFC1123Z))
		if days < 0 {
			fmt.Fprintf(&b, "    status:  EXPIRED %d day(s) ago\r\n", -days)
		} else {
			fmt.Fprintf(&b, "    status:  %d day(s) left\r\n", days)
		}
	}
	b.WriteString("\r\nWhat happens when it lapses:\r\n")
	b.WriteString("  - an expired TLS certificate makes every listener using TLS refuse\r\n")
	b.WriteString("    submissions, so devices stop being able to send.\r\n")
	b.WriteString("  - an expired client secret makes every delivery on that route fail\r\n")
	b.WriteString("    authentication, so mail queues up until it is renewed.\r\n")
	b.WriteString("\r\nThis warning repeats once a day while the deadline is inside the window.\r\n")
	return subject, b.String()
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
