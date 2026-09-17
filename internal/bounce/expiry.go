// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package bounce

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/expiry"
)

const (
	// resendInterval bounds how often the same item is mailed about. Once a
	// day is often enough that an operator cannot miss the window and rare
	// enough that the warning does not become noise they filter away.
	resendInterval = 24 * time.Hour

	// checkInterval is how often the watcher looks. The work is one file
	// read and a date comparison, so this is cheap; it is not shorter
	// because nothing here changes on a scale of minutes.
	checkInterval = time.Hour

	// expirySource names this watcher to bounce.Notifier, which groups by it and
	// looks it up against client names when resolving recipients. A client
	// named this would capture these notifications into its own
	// bounce.notify override; nothing forbids that name, it is simply not
	// one a client is plausibly called.
	expirySource = "expiry-watch"
)

// ExpiryWatcher mails the operator before something the relay depends on
// stops working: its own TLS certificate, or a Microsoft 365 client secret.
//
// It lives here rather than in internal/expiry because deciding that a
// deadline is worth a mail, and sending one, is this package's job -- it
// already owns the operator notification channel and the bounce.notify
// contacts. internal/expiry answers only "what expires and when", which is
// what lets the dashboard and the metrics endpoint read the same deadlines
// without pulling the mail path in behind them.
//
// Both failures are total: an expired certificate refuses every TLS
// submission, an expired secret fails every delivery on that route. Before
// this existed the certificate was announced nowhere and the secret only
// once at startup, which a service running for months never repeats.
//
// It holds no state that must survive a restart: a restart re-checks
// immediately and mails again if anything is inside the window, which is the
// safe direction to err in for a warning.
type ExpiryWatcher struct {
	cfg      *config.Config
	notifier *Notifier
	log      *slog.Logger

	// lastSent is read and written only from Run's own goroutine, or
	// directly by a test.
	lastSent map[string]time.Time
}

// NewExpiryWatcher builds a watcher. It does nothing until Run is started.
func NewExpiryWatcher(cfg *config.Config, n *Notifier, log *slog.Logger) *ExpiryWatcher {
	return &ExpiryWatcher{
		cfg: cfg, notifier: n,
		log:      log.With("component", "expiry"),
		lastSent: map[string]time.Time{},
	}
}

// Run checks immediately and then every checkInterval until ctx is
// cancelled. The immediate check matters: an operator restarting a service
// whose certificate expires next week should hear about it now, not in an
// hour.
func (w *ExpiryWatcher) Run(ctx context.Context) {
	if expiry.WarnWindow(w.cfg) <= 0 {
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
func (w *ExpiryWatcher) check(now time.Time) {
	due := []expiry.Item{}
	for _, it := range w.collect(now) {
		if last, ok := w.lastSent[it.Key]; ok && now.Sub(last) < resendInterval {
			continue
		}
		due = append(due, it)
	}
	if len(due) == 0 {
		return
	}

	subject, body := composeExpiry(due, now, w.cfg.Service.Hostname, w.cfg.Expiry.WarnDays)
	if err := w.notifier.Notify(expirySource, subject, body, now); err != nil {
		// Not marked as sent, so the next check tries again.
		w.log.Error("sending expiry warning failed", "error", err)
		return
	}
	for _, it := range due {
		w.lastSent[it.Key] = now
		w.log.Warn("expiry warning sent", "item", it.What, "expires", it.Expires.Format(time.RFC3339))
	}
}

// collect returns everything expiring inside the expiry.WarnWindow, already
// expired included: an expiry that has passed is the case an operator most
// needs told about, so it is reported rather than dropped for being out of
// range.
func (w *ExpiryWatcher) collect(now time.Time) []expiry.Item {
	// Checked before anything is read. Run already returns early when the
	// window is zero, so this is unreachable in the service -- but reading a
	// certificate and logging about it hourly for warnings that are switched
	// off is not what the disabled state should cost.
	window := expiry.WarnWindow(w.cfg)
	if window <= 0 {
		return nil
	}
	all, certErr := expiry.Items(w.cfg)
	if certErr != nil {
		// Worth a log line, not a mail: see expiry.Items.
		w.log.Warn("cannot read the TLS certificate to check its expiry",
			"file", w.cfg.TLS.CertFile, "error", certErr)
	}
	deadline := now.Add(window)
	var due []expiry.Item
	for _, it := range all {
		if it.Expires.Before(deadline) {
			due = append(due, it)
		}
	}
	return due
}

// composeExpiry renders the message. It says what breaks when each item lapses,
// because the recipient of this mail is not necessarily the person who
// configured the relay.
func composeExpiry(due []expiry.Item, now time.Time, hostname string, windowDays int) (subject, body string) {
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
		subject = fmt.Sprintf("[smtprelayd] %s expires in %d day(s)", due[0].What, expiry.DaysUntil(due[0].Expires, now))
	default:
		subject = fmt.Sprintf("[smtprelayd] %d item(s) expire within %d days on %s",
			len(due), windowDays, hostname)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "smtprelayd on %s is reporting that the following will stop working:\r\n", hostname)
	for _, it := range due {
		days := expiry.DaysUntil(it.Expires, now)
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
