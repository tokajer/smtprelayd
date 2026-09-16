// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package expiry

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/certgen"
	"github.com/tokajer/smtprelayd/internal/config"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// writeCert puts a real certificate on disk expiring at the given offset
// from now, so the parsing path is exercised rather than stubbed.
func writeCert(t *testing.T, validity time.Duration) string {
	t.Helper()
	certPEM, _, err := certgen.Generate(certgen.Options{
		Hosts: []string{"relay.internal.example.at"}, Validity: validity,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "relay.crt")
	if err := os.WriteFile(path, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func watcher(t *testing.T, cfg *config.Config) *Watcher {
	t.Helper()
	// A nil notifier is fine for collect/compose tests: they never send.
	return New(cfg, nil, discardLog())
}

func TestCertificateInsideTheWindowIsCollected(t *testing.T) {
	now := time.Now()
	cfg := &config.Config{TLS: config.TLS{CertFile: writeCert(t, 10*24*time.Hour)}}

	items := watcher(t, cfg).collect(now)
	if len(items) != 1 {
		t.Fatalf("collect() = %v, want the certificate", items)
	}
	if items[0].key != "tls-certificate" {
		t.Errorf("key = %q, want %q", items[0].key, "tls-certificate")
	}
}

func TestCertificateOutsideTheWindowIsIgnored(t *testing.T) {
	cfg := &config.Config{TLS: config.TLS{CertFile: writeCert(t, 90*24*time.Hour)}}
	if items := watcher(t, cfg).collect(time.Now()); len(items) != 0 {
		t.Fatalf("collect() = %v, want nothing 90 days out", items)
	}
}

// An expiry that has already passed is the case an operator most needs told
// about, so it must not fall out of range.
func TestAlreadyExpiredCertificateIsStillReported(t *testing.T) {
	now := time.Now()
	// Generated against a clock two years back, so it is long expired.
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

	items := watcher(t, &config.Config{TLS: config.TLS{CertFile: path}}).collect(now)
	if len(items) != 1 {
		t.Fatalf("collect() = %v, want the expired certificate", items)
	}
}

// An unreadable certificate is a log line, not a mail: the listener would
// not have started on one, so this is a file that changed under a running
// service and mailing about it helps nobody.
func TestUnreadableCertificateIsNotReportedAsAnItem(t *testing.T) {
	cfg := &config.Config{TLS: config.TLS{CertFile: filepath.Join(t.TempDir(), "absent.crt")}}
	if items := watcher(t, cfg).collect(time.Now()); len(items) != 0 {
		t.Fatalf("collect() = %v, want nothing for an unreadable file", items)
	}
}

func TestOAuth2SecretExpiryIsCollectedPerRoute(t *testing.T) {
	now := time.Now()
	soon := now.Add(5 * 24 * time.Hour).Format("2006-01-02")
	far := now.Add(300 * 24 * time.Hour).Format("2006-01-02")
	cfg := &config.Config{Routes: []config.Route{
		{Name: "m365", Auth: "xoauth2", OAuth2: config.OAuth2{TenantID: "t", SecretExpires: soon}},
		{Name: "later", Auth: "xoauth2", OAuth2: config.OAuth2{TenantID: "t", SecretExpires: far}},
		// Not xoauth2, so it has no secret to expire.
		{Name: "plain", Auth: "plain", OAuth2: config.OAuth2{SecretExpires: soon}},
		// xoauth2 but no expiry recorded: nothing to check.
		{Name: "undated", Auth: "xoauth2"},
	}}

	items := watcher(t, cfg).collect(now)
	if len(items) != 1 {
		t.Fatalf("collect() = %v, want only the m365 secret", items)
	}
	if items[0].key != "oauth2-secret:m365" {
		t.Errorf("key = %q, want %q", items[0].key, "oauth2-secret:m365")
	}
}

// The repeat gate is what keeps a daily warning from becoming an hourly one.
func TestAnItemIsNotRepeatedWithinTheResendInterval(t *testing.T) {
	now := time.Now()
	w := watcher(t, &config.Config{TLS: config.TLS{CertFile: writeCert(t, 10*24*time.Hour)}})
	w.lastSent["tls-certificate"] = now.Add(-2 * time.Hour)

	var due []item
	for _, it := range w.collect(now) {
		if last, ok := w.lastSent[it.key]; ok && now.Sub(last) < resendInterval {
			continue
		}
		due = append(due, it)
	}
	if len(due) != 0 {
		t.Fatalf("an item mailed 2h ago was due again: %v", due)
	}

	// Once the interval has passed it must come back.
	w.lastSent["tls-certificate"] = now.Add(-25 * time.Hour)
	due = nil
	for _, it := range w.collect(now) {
		if last, ok := w.lastSent[it.key]; ok && now.Sub(last) < resendInterval {
			continue
		}
		due = append(due, it)
	}
	if len(due) != 1 {
		t.Fatalf("an item mailed 25h ago was not due again: %v", due)
	}
}

func TestComposeNamesTheItemAndItsDeadline(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	due := []item{{
		key: "tls-certificate", what: "the listener TLS certificate",
		detail: "/etc/smtprelayd/tls/relay.crt", expires: now.Add(7 * 24 * time.Hour),
	}}

	subject, body := compose(due, now, "relay.internal.example.at")
	if !strings.Contains(subject, "7 day") {
		t.Errorf("subject = %q, want the days remaining", subject)
	}
	for _, want := range []string{
		"the listener TLS certificate", "/etc/smtprelayd/tls/relay.crt", "7 day(s) left",
		"relay.internal.example.at",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body is missing %q:\n%s", want, body)
		}
	}
}

// An already-lapsed item must read as lapsed, not as "0 days left".
func TestComposeMarksAnExpiredItem(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	due := []item{{
		key: "oauth2-secret:m365", what: "the Microsoft 365 client secret for route \"m365\"",
		detail: "tenant contoso.onmicrosoft.com", expires: now.Add(-3 * 24 * time.Hour),
	}}

	subject, body := compose(due, now, "relay")
	if !strings.Contains(subject, "ACTION REQUIRED") || !strings.Contains(subject, "expired") {
		t.Errorf("subject = %q, want it to flag an expired item", subject)
	}
	if !strings.Contains(body, "EXPIRED 3 day(s) ago") {
		t.Errorf("body should say how long ago it expired:\n%s", body)
	}
}

func TestComposeBatchesSeveralItems(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	due := []item{
		{key: "a", what: "item A", detail: "d", expires: now.Add(2 * 24 * time.Hour)},
		{key: "b", what: "item B", detail: "d", expires: now.Add(9 * 24 * time.Hour)},
	}
	subject, body := compose(due, now, "relay")
	if !strings.Contains(subject, "2 item(s)") {
		t.Errorf("subject = %q, want it to count both", subject)
	}
	if !strings.Contains(body, "item A") || !strings.Contains(body, "item B") {
		t.Errorf("body should list both:\n%s", body)
	}
}

func TestNoCertificateAndNoRoutesCollectsNothing(t *testing.T) {
	if items := watcher(t, &config.Config{}).collect(time.Now()); len(items) != 0 {
		t.Fatalf("collect() = %v, want nothing", items)
	}
}

func TestCertNotAfterSkipsNonCertificateBlocks(t *testing.T) {
	certPEM, keyPEM, err := certgen.Generate(certgen.Options{Hosts: []string{"h"}, Validity: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	// Key first, as some tooling writes combined PEM files: the certificate
	// must still be found rather than the key being parsed as one.
	path := filepath.Join(t.TempDir(), "combined.pem")
	if err := os.WriteFile(path, append(keyPEM, certPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := certNotAfter(path); err != nil {
		t.Fatalf("certNotAfter on a combined PEM: %v", err)
	}
}
