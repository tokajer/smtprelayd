// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package smarthost

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

// selfSigned builds a throwaway certificate. Only its bytes matter here: the
// pin is a digest and never a signature check of its own.
func selfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func TestPinVerifierAcceptsCertificateInVerifiedChain(t *testing.T) {
	ca := selfSigned(t, "pinned ca")
	leaf := selfSigned(t, "smarthost")

	err := pinVerifier(fingerprint(ca))(tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{leaf, ca}},
	})
	if err != nil {
		t.Fatalf("pinned CA in the verified chain was rejected: %v", err)
	}
}

// TestPinVerifierIgnoresCertificatesOutsideTheVerifiedChain is the regression
// test for the bypass: a server that holds any publicly trusted certificate
// for the host used to satisfy the pin by appending the pinned certificate as
// an unused extra element of what it sent.
func TestPinVerifierIgnoresCertificatesOutsideTheVerifiedChain(t *testing.T) {
	pinned := selfSigned(t, "pinned ca")
	attackerLeaf := selfSigned(t, "smarthost")
	attackerCA := selfSigned(t, "some other publicly trusted ca")

	err := pinVerifier(fingerprint(pinned))(tls.ConnectionState{
		// The chain that actually verified contains only the attacker's
		// certificates; the pinned one was merely presented alongside it.
		VerifiedChains:   [][]*x509.Certificate{{attackerLeaf, attackerCA}},
		PeerCertificates: []*x509.Certificate{attackerLeaf, attackerCA, pinned},
	})
	if err == nil {
		t.Fatal("a certificate outside the verified chain satisfied ca_pin")
	}
}

func TestPinVerifierRejectsUnpinnedChain(t *testing.T) {
	pinned := selfSigned(t, "pinned ca")

	err := pinVerifier(fingerprint(pinned))(tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{selfSigned(t, "leaf"), selfSigned(t, "other ca")}},
	})
	if err == nil {
		t.Fatal("an unrelated chain satisfied ca_pin")
	}
}

func TestPinVerifierRejectsEmptyChain(t *testing.T) {
	if err := pinVerifier(fingerprint(selfSigned(t, "ca")))(tls.ConnectionState{}); err == nil {
		t.Fatal("an empty verified chain satisfied ca_pin")
	}
}
