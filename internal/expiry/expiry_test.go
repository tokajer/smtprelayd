// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package expiry

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/certgen"
	"github.com/tokajer/smtprelayd/internal/config"
)

// genCert builds a real leaf certificate expiring at the given offset from
// now, so the parsing path is exercised rather than stubbed. It stands in for
// what cmd/smtprelayd's loadCertificate hands to Items as the served
// certificate.
func genCert(t *testing.T, validity time.Duration) *x509.Certificate {
	t.Helper()
	certPEM, _, err := certgen.Generate(certgen.Options{
		Hosts: []string{"relay.internal.example.at"}, Validity: validity,
	})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block in the generated certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// Items reports every deadline regardless of how far away it is: the window
// is the caller's business, and the dashboard shows healthy ones too.
func TestItemsReportsTheCertificateWhateverItsDistance(t *testing.T) {
	for _, validity := range []time.Duration{10 * 24 * time.Hour, 900 * 24 * time.Hour} {
		cfg := &config.Config{TLS: config.TLS{CertFile: "relay.crt"}}
		items := Items(cfg, genCert(t, validity))
		if len(items) != 1 {
			t.Fatalf("validity %v: Items() = %v, want the certificate", validity, items)
		}
		if items[0].Key != "tls-certificate" {
			t.Errorf("key = %q, want %q", items[0].Key, "tls-certificate")
		}
	}
}

// No served certificate means none is configured (or the listener refused to
// start on it, in which case the process never reaches Items at all): either
// way there is nothing to report.
func TestItemsWithNoServedCertificateReportsNoCertificate(t *testing.T) {
	cfg := &config.Config{TLS: config.TLS{CertFile: "relay.crt"}}
	items := Items(cfg, nil)
	for _, it := range items {
		if it.Key == "tls-certificate" {
			t.Fatalf("Items() with no served certificate reported one: %v", items)
		}
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

	items := Items(cfg, nil)
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
		TLS: config.TLS{CertFile: "relay.crt"},
		Routes: []config.Route{{Name: "m365", Auth: "xoauth2", OAuth2: config.OAuth2{
			TenantID: "t", SecretExpires: now.Add(5 * 24 * time.Hour).Format("2006-01-02"),
		}}},
	}
	items := Items(cfg, genCert(t, 200*24*time.Hour))
	if len(items) != 2 || items[0].Key != "oauth2-secret:m365" {
		t.Fatalf("Items() = %v, want the secret first", items)
	}
}

func TestItemsWithNothingConfigured(t *testing.T) {
	items := Items(&config.Config{}, nil)
	if len(items) != 0 {
		t.Fatalf("Items() = %v, want nothing", items)
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
