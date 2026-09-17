// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/tokajer/smtprelayd/internal/config"
)

var tokenLine = regexp.MustCompile(`token:  (\S+)`)
var digestLine = regexp.MustCompile(`sha256: ([0-9a-f]{64})`)

// The pair has to be usable: the printed digest is what goes into the
// configuration, and the printed token is what a caller presents. If they do
// not match through config.MatchToken, the command has produced a credential
// that can never authenticate.
func TestNewTokenProducesAMatchingPair(t *testing.T) {
	var out strings.Builder
	if err := newToken("read", &out); err != nil {
		t.Fatal(err)
	}
	m := tokenLine.FindStringSubmatch(out.String())
	d := digestLine.FindStringSubmatch(out.String())
	if m == nil || d == nil {
		t.Fatalf("output is missing the token or the digest:\n%s", out.String())
	}
	token, digest := m[1], d[1]

	sum := sha256.Sum256([]byte(token))
	if hex.EncodeToString(sum[:]) != digest {
		t.Fatal("the printed digest is not the digest of the printed token")
	}

	cfg := &config.Config{Web: config.Web{Tokens: []config.Token{
		{Name: "checkmk", Scope: "read", SHA256: digest},
	}}}
	got, ok := cfg.MatchToken(token)
	if !ok {
		t.Fatal("the generated token does not authenticate against its own digest")
	}
	if got.Name != "checkmk" {
		t.Errorf("matched token %q, want checkmk", got.Name)
	}
	if cfg.MatchToken(token + "x"); false {
		t.Fatal("unreachable")
	}
	if _, ok := cfg.MatchToken(token + "x"); ok {
		t.Error("a modified token still authenticated")
	}
}

// 256 bits, per docs/guides/SECURITY.md: a shorter token would be the weak
// half of a pair whose digest is 256 bits wide.
func TestNewTokenCarries256Bits(t *testing.T) {
	var out strings.Builder
	if err := newToken("admin", &out); err != nil {
		t.Fatal(err)
	}
	token := tokenLine.FindStringSubmatch(out.String())[1]
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not RawURLEncoding, so it may not survive a header: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("token carries %d bytes, want 32", len(raw))
	}
	if strings.ContainsAny(token, "+/= ") {
		t.Errorf("token %q contains a character that needs escaping somewhere", token)
	}
}

// Two runs must not repeat, or the entropy is not coming from crypto/rand.
func TestNewTokenDiffersBetweenRuns(t *testing.T) {
	var a, b strings.Builder
	if err := newToken("read", &a); err != nil {
		t.Fatal(err)
	}
	if err := newToken("read", &b); err != nil {
		t.Fatal(err)
	}
	if tokenLine.FindStringSubmatch(a.String())[1] == tokenLine.FindStringSubmatch(b.String())[1] {
		t.Fatal("two generated tokens are identical")
	}
}

func TestNewTokenScopeIsValidated(t *testing.T) {
	var out strings.Builder
	for _, scope := range []string{"read", "admin"} {
		if err := newToken(scope, &out); err != nil {
			t.Errorf("scope %q rejected: %v", scope, err)
		}
		if !strings.Contains(out.String(), `scope  = "`+scope+`"`) {
			t.Errorf("the pasteable block does not carry scope %q", scope)
		}
		out.Reset()
	}
	// Anything else would produce a block config.Validate then refuses,
	// which is a worse place to find out.
	for _, scope := range []string{"", "write", "Admin"} {
		if err := newToken(scope, &out); err == nil {
			t.Errorf("scope %q was accepted", scope)
		}
	}
}
