// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package expiry

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/certgen"
	"github.com/tokajer/smtprelayd/internal/config"
)

// writeCert puts a real certificate on disk expiring at the given offset from
// now, so the parsing path is exercised rather than stubbed.
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

// Items reports every deadline regardless of how far away it is: the window
// is the caller's business, and the dashboard shows healthy ones too.
func TestItemsReportsTheCertificateWhateverItsDistance(t *testing.T) {
	for _, validity := range []time.Duration{10 * 24 * time.Hour, 900 * 24 * time.Hour} {
		cfg := &config.Config{TLS: config.TLS{CertFile: writeCert(t, validity)}}
		items, err := Items(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 1 {
			t.Fatalf("validity %v: Items() = %v, want the certificate", validity, items)
		}
		if items[0].Key != "tls-certificate" {
			t.Errorf("key = %q, want %q", items[0].Key, "tls-certificate")
		}
	}
}

// An unreadable certificate is an error, not an Item: the listener would not
// have started on one, so it means the file changed under a running service.
func TestItemsReportsAnUnreadableCertificateAsAnError(t *testing.T) {
	cfg := &config.Config{TLS: config.TLS{CertFile: filepath.Join(t.TempDir(), "absent.crt")}}
	items, err := Items(cfg)
	if err == nil {
		t.Fatal("an unreadable certificate must be reported as an error")
	}
	if len(items) != 0 {
		t.Errorf("Items() = %v, want nothing", items)
	}
}

func TestItemsCollectsOAuth2SecretsPerRoute(t *testing.T) {
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

	items, err := Items(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("Items() = %v, want the two dated xoauth2 routes", items)
	}
	// Soonest first, which is what both the mail and the dashboard rely on.
	if items[0].Key != "oauth2-secret:m365" || items[1].Key != "oauth2-secret:later" {
		t.Errorf("Items() = %v, want m365 before later", items)
	}
}

func TestItemsSortsSoonestFirst(t *testing.T) {
	now := time.Now()
	cfg := &config.Config{
		TLS: config.TLS{CertFile: writeCert(t, 200*24*time.Hour)},
		Routes: []config.Route{{Name: "m365", Auth: "xoauth2", OAuth2: config.OAuth2{
			TenantID: "t", SecretExpires: now.Add(5 * 24 * time.Hour).Format("2006-01-02"),
		}}},
	}
	items, err := Items(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Key != "oauth2-secret:m365" {
		t.Fatalf("Items() = %v, want the secret first", items)
	}
}

func TestItemsWithNothingConfigured(t *testing.T) {
	items, err := Items(&config.Config{})
	if err != nil || len(items) != 0 {
		t.Fatalf("Items() = %v, %v, want nothing and no error", items, err)
	}
}

func TestWarnWindow(t *testing.T) {
	if got := WarnWindow(&config.Config{Expiry: config.Expiry{WarnDays: 30}}); got != 30*24*time.Hour {
		t.Errorf("WarnWindow(30) = %v", got)
	}
	// Zero switches the warnings off; the caller checks for it.
	if got := WarnWindow(&config.Config{}); got != 0 {
		t.Errorf("WarnWindow(0) = %v, want 0", got)
	}
}

func TestDaysUntil(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	// Truncating, not rounding: "1 day left" must not be printed for
	// something lapsing in an hour.
	if got := DaysUntil(now.Add(47*time.Hour), now); got != 1 {
		t.Errorf("DaysUntil(47h) = %d, want 1", got)
	}
	if got := DaysUntil(now.Add(-3*24*time.Hour), now); got != -3 {
		t.Errorf("DaysUntil(-3d) = %d, want -3", got)
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
