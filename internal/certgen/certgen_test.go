// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package certgen

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func parse(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		t.Fatalf("certificate PEM did not decode, got block %v", blk)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The pair has to be loadable by the same call the listener uses, or the
// command has produced files that only fail at startup.
func TestGeneratedPairLoadsAsATLSKeypair(t *testing.T) {
	certPEM, keyPEM, err := Generate(Options{Hosts: []string{"relay.internal.example.at"}})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair rejected the generated pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	key, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *rsa.PublicKey for legacy device compatibility", leaf.PublicKey)
	}
	if bits := key.N.BitLen(); bits != keyBits {
		t.Errorf("key is %d bits, want %d", bits, keyBits)
	}
}

// An entry that parses as an IP has to become an IP SAN: a client connecting
// to a bare address matches nothing against a DNS SAN of the same text.
func TestHostsAreSplitIntoDNSAndIPSANs(t *testing.T) {
	certPEM, _, err := Generate(Options{Hosts: []string{
		"relay.internal.example.at", "10.10.5.1", "localhost", "127.0.0.1", "::1",
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := parse(t, certPEM)

	wantDNS := []string{"relay.internal.example.at", "localhost"}
	if len(c.DNSNames) != len(wantDNS) {
		t.Fatalf("DNSNames = %v, want %v", c.DNSNames, wantDNS)
	}
	for i, w := range wantDNS {
		if c.DNSNames[i] != w {
			t.Errorf("DNSNames[%d] = %q, want %q", i, c.DNSNames[i], w)
		}
	}
	if len(c.IPAddresses) != 3 {
		t.Fatalf("IPAddresses = %v, want 3 entries", c.IPAddresses)
	}
	if c.Subject.CommonName != "relay.internal.example.at" {
		t.Errorf("CommonName = %q, want the first host", c.Subject.CommonName)
	}
}

// Hostname verification is the property that makes the certificate usable by
// a client that checks anything, so verify it the way such a client would.
func TestCertificateVerifiesAgainstItselfForEveryName(t *testing.T) {
	certPEM, _, err := Generate(Options{Hosts: []string{"relay.internal.example.at", "10.10.5.1"}})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("the generated certificate was not accepted into a pool")
	}
	c := parse(t, certPEM)
	for _, name := range []string{"relay.internal.example.at", "10.10.5.1"} {
		if _, err := c.Verify(x509.VerifyOptions{DNSName: name, Roots: roots}); err != nil {
			t.Errorf("verifying for %q: %v", name, err)
		}
	}
	// A name it was not issued for must still fail, or the SAN list means
	// nothing.
	if _, err := c.Verify(x509.VerifyOptions{DNSName: "elsewhere.example.com", Roots: roots}); err == nil {
		t.Error("the certificate verified for a name it does not carry")
	}
}

func TestValidityIsHonouredAndBackdated(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	certPEM, _, err := Generate(Options{
		Hosts: []string{"relay.internal.example.at"}, Validity: 48 * time.Hour, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	c := parse(t, certPEM)
	if !c.NotAfter.Equal(now.Add(48 * time.Hour)) {
		t.Errorf("NotAfter = %v, want %v", c.NotAfter, now.Add(48*time.Hour))
	}
	// Backdated, so a client whose clock trails the relay's still accepts a
	// certificate generated moments ago.
	if !c.NotBefore.Before(now) {
		t.Errorf("NotBefore = %v, want it before %v", c.NotBefore, now)
	}
}

func TestDefaultValidityApplies(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	certPEM, _, err := Generate(Options{Hosts: []string{"h"}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if c := parse(t, certPEM); !c.NotAfter.Equal(now.Add(DefaultValidity)) {
		t.Errorf("NotAfter = %v, want %v", c.NotAfter, now.Add(DefaultValidity))
	}
}

// It is a server certificate, not an authority: signing anything else with
// it must not be possible.
func TestCertificateIsNotACA(t *testing.T) {
	certPEM, _, err := Generate(Options{Hosts: []string{"relay.internal.example.at"}})
	if err != nil {
		t.Fatal(err)
	}
	c := parse(t, certPEM)
	if c.IsCA {
		t.Error("the generated certificate claims to be a CA")
	}
	if !c.BasicConstraintsValid {
		t.Error("basic constraints must be present and valid")
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage = %v, want exactly ServerAuth", c.ExtKeyUsage)
	}
}

func TestNoHostsIsRejected(t *testing.T) {
	if _, _, err := Generate(Options{}); err == nil {
		t.Fatal("a certificate with no SAN matches no name and must be refused")
	}
	if _, _, err := Generate(Options{Hosts: []string{"", ""}}); err == nil {
		t.Fatal("hosts that are all empty must be refused")
	}
}

func TestDuplicateHostsAppearOnce(t *testing.T) {
	certPEM, _, err := Generate(Options{Hosts: []string{"relay", "relay", "127.0.0.1", "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	c := parse(t, certPEM)
	if len(c.DNSNames) != 1 || len(c.IPAddresses) != 1 {
		t.Errorf("DNSNames = %v, IPAddresses = %v, want one of each", c.DNSNames, c.IPAddresses)
	}
}

// Two runs must not produce the same serial: a serial has to be unique per
// issuer, and this issuer keeps no state between runs to count with.
func TestSerialsDiffer(t *testing.T) {
	a, _, err := Generate(Options{Hosts: []string{"h"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Generate(Options{Hosts: []string{"h"}})
	if err != nil {
		t.Fatal(err)
	}
	if parse(t, a).SerialNumber.Cmp(parse(t, b).SerialNumber) == 0 {
		t.Error("two generated certificates share a serial number")
	}
}
