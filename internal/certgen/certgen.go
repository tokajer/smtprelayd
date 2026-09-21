// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package certgen creates a self-signed certificate for the relay's own
// inbound listeners.
//
// It exists for the deployment this relay is actually for: an internal
// listener that legacy devices submit to, where there is no public name and
// no CA in the picture. It has nothing to do with outbound delivery, where
// certificate verification against the system roots is mandatory and is
// never relaxed -- see docs/guides/SECURITY.md. Nothing in this package can
// affect that path; it only produces bytes for the caller to write.
package certgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// keyBits is RSA, not ECDSA, deliberately. docs/guides/SECURITY.md keeps
// TLS 1.0 reachable on the internal port 25 listener because the devices
// this relay serves are printers and MFPs that predate widespread ECDSA
// support; a key those clients cannot negotiate would turn an operator
// convenience into a support call. 2048 bits is the floor every such client
// accepts and is generated in well under a second.
const keyBits = 2048

// DefaultValidity is how long a generated certificate lasts. Long enough
// that renewal is not routine toil, short enough that a key which leaks does
// not stay valid indefinitely.
//
// The approaching expiry is warned about in three places, none of them here:
// internal/expiry reads the deadline, bounce.ExpiryWatcher mails about it,
// and smtprelayd_expiry_seconds exposes it. The date this command prints is
// the first notice, not the only one.
const DefaultValidity = 825 * 24 * time.Hour

// Options describes the certificate to produce.
type Options struct {
	// Hosts are the subject alternative names. An entry that parses as an IP
	// address becomes an IP SAN, everything else a DNS SAN. At least one is
	// required: a certificate with no SAN matches no name at all, which
	// every client that verifies anything will reject.
	Hosts []string

	// Validity defaults to DefaultValidity when zero.
	Validity time.Duration

	// Now defaults to time.Now. Set by tests so expiry is assertable.
	Now time.Time
}

// Generate returns a PEM-encoded self-signed certificate and its private
// key. The key is returned, never written: choosing where a private key
// lands, and with what permissions, belongs to the caller.
func Generate(o Options) (certPEM, keyPEM []byte, err error) {
	hosts := dedupe(o.Hosts)
	if len(hosts) == 0 {
		return nil, nil, errors.New("certgen: at least one host is required")
	}
	validity := o.Validity
	if validity <= 0 {
		validity = DefaultValidity
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}

	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("certgen: generating key: %w", err)
	}

	// 128 bits from crypto/rand rather than a counter: a serial has to be
	// unique across every certificate a given issuer ever signs, and this
	// issuer keeps no state between runs to count with.
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return nil, nil, fmt.Errorf("certgen: generating serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"smtprelayd self-signed"}},
		// Backdated by an hour so a client whose clock runs behind the
		// relay's does not reject a certificate generated moments ago.
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(validity),
		// KeyEncipherment alongside DigitalSignature because a client old
		// enough to need TLS 1.0 may still negotiate RSA key exchange, which
		// uses the certificate key to encrypt the premaster secret.
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// This is a server certificate, not a certificate authority. It is
		// trusted, where it is trusted at all, by being imported explicitly
		// or pinned -- never by signing anything else.
		IsCA: false,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("certgen: signing certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustMarshalKey(key),
	})
	return certPEM, keyPEM, nil
}

// mustMarshalKey cannot fail for an *rsa.PrivateKey: MarshalPKCS8PrivateKey
// only rejects key types it does not know, and this one is always RSA.
func mustMarshalKey(key *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic("certgen: marshalling an RSA key cannot fail: " + err.Error())
	}
	return der
}

// dedupe preserves order and drops empties, so that a hostname which is also
// a listener bind address does not appear twice in the SAN list.
func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
