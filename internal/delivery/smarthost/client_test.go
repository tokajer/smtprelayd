// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package smarthost

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
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

// A cancelled context must abort an attempt that is already past the dial.
// net/smtp takes no context, so without the deadline trick in Deliver this
// blocks until the timeout -- tolerable under systemd's 90s default, fatal
// under the Windows SCM's five seconds, where the service is killed for not
// responding to a stop.
func TestDeliverAbortsInFlightOnContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// A server that greets and then never speaks again: Deliver is left
	// waiting on a read it can only leave via the deadline.
	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("220 stub ESMTP\r\n"))
		close(accepted)
		select {} // hold the connection open, answer nothing
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	route := config.Route{Name: "stub", Host: host, Port: port, TLS: "none", Auth: "none"}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Deliver(ctx, route, Message{
			From: "a@example.at", To: []string{"b@example.at"},
			Data: strings.NewReader("Subject: t\r\n\r\nbody\r\n"), Helo: "test",
		}, time.Hour, nil) // an hour, so only cancellation can end this
	}()

	<-accepted
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Deliver returned success against a server that never replied")
		}
		// Temporary, so the message stays queued for the next start rather
		// than being moved to spool/failed by a shutdown.
		var te *TempError
		if !errors.As(err, &te) {
			t.Errorf("error is %T (%v), want a TempError so the message is retried", err, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Deliver ignored the cancelled context and was still running after 10s")
	}
}
