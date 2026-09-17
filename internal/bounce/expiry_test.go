// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package bounce

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/certgen"
	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/expiry"
)

func certExpiringIn(t *testing.T, d time.Duration) string {
	t.Helper()
	certPEM, _, err := certgen.Generate(certgen.Options{Hosts: []string{"relay"}, Validity: d})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "relay.crt")
	if err := os.WriteFile(path, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func watcherFor(t *testing.T, cfg *config.Config) *ExpiryWatcher {
	t.Helper()
	// A nil notifier is fine for collect and compose: they never send.
	return NewExpiryWatcher(cfg, nil, discardLog())
}

// warn_days is the lead time, so raising it must pull a distant deadline into
// the window. That is how an operator triggers the mail deliberately to check
// the path works, and it is documented as such.
func TestWarnDaysWidensAndDisablesTheWindow(t *testing.T) {
	now := time.Now()
	certFile := certExpiringIn(t, 90*24*time.Hour)

	cfg := &config.Config{TLS: config.TLS{CertFile: certFile}, Expiry: config.Expiry{WarnDays: 30}}
	if items := watcherFor(t, cfg).collect(now); len(items) != 0 {
		t.Fatalf("30 days: got %v, want nothing 90 days out", items)
	}

	cfg.Expiry.WarnDays = 120
	if items := watcherFor(t, cfg).collect(now); len(items) != 1 {
		t.Fatalf("120 days: got %v, want the certificate", items)
	}

	// Zero switches the warnings off entirely, however close the deadline.
	near := &config.Config{TLS: config.TLS{CertFile: certExpiringIn(t, 24*time.Hour)}}
	if items := watcherFor(t, near).collect(now); len(items) != 0 {
		t.Fatalf("warn_days 0: got %v, want nothing", items)
	}
}

// An expiry that has already passed is the case an operator most needs told
// about, so it must not fall out of range for being behind rather than ahead.
func TestAlreadyExpiredIsStillCollected(t *testing.T) {
	now := time.Now()
	certPEM, _, err := certgen.Generate(certgen.Options{
		Hosts: []string{"old"}, Validity: 24 * time.Hour, Now: now.Add(-2 * 365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "old.crt")
	if err := os.WriteFile(path, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{TLS: config.TLS{CertFile: path}, Expiry: config.Expiry{WarnDays: 30}}
	if items := watcherFor(t, cfg).collect(now); len(items) != 1 {
		t.Fatalf("collect() = %v, want the expired certificate", items)
	}
}

// An unreadable certificate is a log line, not a mail: the listener would not
// have started on one, so mailing about it helps nobody.
func TestUnreadableCertificateIsNotCollected(t *testing.T) {
	cfg := &config.Config{
		TLS:    config.TLS{CertFile: filepath.Join(t.TempDir(), "absent.crt")},
		Expiry: config.Expiry{WarnDays: 30},
	}
	if items := watcherFor(t, cfg).collect(time.Now()); len(items) != 0 {
		t.Fatalf("collect() = %v, want nothing for an unreadable file", items)
	}
}

// The repeat gate is what keeps a daily warning from becoming an hourly one.
func TestAnItemIsNotRepeatedWithinTheResendInterval(t *testing.T) {
	now := time.Now()
	cfg := &config.Config{
		TLS:    config.TLS{CertFile: certExpiringIn(t, 10*24*time.Hour)},
		Expiry: config.Expiry{WarnDays: 30},
	}
	w := watcherFor(t, cfg)

	due := func() []expiry.Item {
		var out []expiry.Item
		for _, it := range w.collect(now) {
			if last, ok := w.lastSent[it.Key]; ok && now.Sub(last) < resendInterval {
				continue
			}
			out = append(out, it)
		}
		return out
	}

	w.lastSent["tls-certificate"] = now.Add(-2 * time.Hour)
	if got := due(); len(got) != 0 {
		t.Fatalf("an item mailed 2h ago was due again: %v", got)
	}
	w.lastSent["tls-certificate"] = now.Add(-25 * time.Hour)
	if got := due(); len(got) != 1 {
		t.Fatalf("an item mailed 25h ago was not due again: %v", got)
	}
}

func TestComposeExpiryNamesTheItemAndItsDeadline(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	due := []expiry.Item{{
		Key: "tls-certificate", What: "the listener TLS certificate",
		Detail: "/etc/smtprelayd/tls/relay.crt", Expires: now.Add(7 * 24 * time.Hour),
	}}

	subject, body := composeExpiry(due, now, "relay.internal.example.at", 30)
	if !strings.Contains(subject, "7 day") {
		t.Errorf("subject = %q, want the days remaining", subject)
	}
	for _, want := range []string{
		"the listener TLS certificate", "/etc/smtprelayd/tls/relay.crt",
		"7 day(s) left", "relay.internal.example.at",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body is missing %q:\n%s", want, body)
		}
	}
}

// An already-lapsed item must read as lapsed, not as "0 days left".
func TestComposeExpiryMarksAnExpiredItem(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	due := []expiry.Item{{
		Key: "oauth2-secret:m365", What: `the Microsoft 365 client secret for route "m365"`,
		Detail: "tenant contoso.onmicrosoft.com", Expires: now.Add(-3 * 24 * time.Hour),
	}}

	subject, body := composeExpiry(due, now, "relay", 30)
	if !strings.Contains(subject, "ACTION REQUIRED") || !strings.Contains(subject, "expired") {
		t.Errorf("subject = %q, want it to flag an expired item", subject)
	}
	if !strings.Contains(body, "EXPIRED 3 day(s) ago") {
		t.Errorf("body should say how long ago it expired:\n%s", body)
	}
}

func TestComposeExpiryBatchesSeveralItems(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	due := []expiry.Item{
		{Key: "a", What: "item A", Detail: "d", Expires: now.Add(2 * 24 * time.Hour)},
		{Key: "b", What: "item B", Detail: "d", Expires: now.Add(9 * 24 * time.Hour)},
	}
	subject, body := composeExpiry(due, now, "relay", 30)
	if !strings.Contains(subject, "2 item(s)") {
		t.Errorf("subject = %q, want it to count both", subject)
	}
	if !strings.Contains(body, "item A") || !strings.Contains(body, "item B") {
		t.Errorf("body should list both:\n%s", body)
	}
}
