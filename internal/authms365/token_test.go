// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package authms365

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestSource(t *testing.T, h http.HandlerFunc) *TokenSource {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	ts, err := New(Options{
		TenantID: "contoso.onmicrosoft.com",
		ClientID: "00000000-0000-0000-0000-000000000000",
		Secret:   "s3cret",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts.endpoint = srv.URL
	return ts
}

func tokenResponse(token string, expiresIn int) string {
	return fmt.Sprintf(`{"token_type":"Bearer","expires_in":%d,"access_token":%q}`, expiresIn, token)
}

func TestTokenIsCachedBetweenCalls(t *testing.T) {
	var hits int32
	ts := newTestSource(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if err := r.ParseForm(); err != nil {
			t.Errorf("form: %v", err)
		}
		if got := r.PostFormValue("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q", got)
		}
		if got := r.PostFormValue("scope"); got != "https://outlook.office365.com/.default" {
			t.Errorf("scope = %q", got)
		}
		fmt.Fprint(w, tokenResponse("abc.def", 3600))
	})

	for i := 0; i < 3; i++ {
		got, err := ts.Token(context.Background())
		if err != nil {
			t.Fatalf("Token: %v", err)
		}
		if got != "abc.def" {
			t.Fatalf("token = %q", got)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("token endpoint called %d times, want 1", n)
	}
}

func TestTokenIsRenewedBeforeExpiry(t *testing.T) {
	var hits int32
	ts := newTestSource(t, func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		// Shorter than refreshSkew, so the cached value is never handed out.
		fmt.Fprint(w, tokenResponse(fmt.Sprintf("token%d", n), 120))
	})

	first, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	second, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if first == second {
		t.Fatal("a token inside the refresh window was reused")
	}
	if n := atomic.LoadInt32(&hits); n != 2 {
		t.Fatalf("token endpoint called %d times, want 2", n)
	}
}

func TestRejectedRequestIsThrottled(t *testing.T) {
	var hits int32
	ts := newTestSource(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}`)
	})

	_, err := ts.Token(context.Background())
	if err == nil {
		t.Fatal("a rejected token request returned no error")
	}
	if !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := ts.Token(context.Background()); err == nil {
		t.Fatal("second call returned no error")
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Fatalf("token endpoint called %d times during the cooldown, want %d", n, 1)
	}
}

func TestStaleTokenSurvivesAFailedRefresh(t *testing.T) {
	var hits int32
	ts := newTestSource(t, func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			fmt.Fprint(w, tokenResponse("still.valid", 120))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	got, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("a failed refresh discarded a token that was still valid: %v", err)
	}
	if got != "still.valid" {
		t.Fatalf("token = %q", got)
	}
}

func TestUnusableResponsesAreRefused(t *testing.T) {
	cases := map[string]string{
		"non-bearer type":  `{"token_type":"Mac","expires_in":3600,"access_token":"abc"}`,
		"empty token":      `{"token_type":"Bearer","expires_in":3600,"access_token":""}`,
		"no expiry":        `{"token_type":"Bearer","expires_in":0,"access_token":"abc"}`,
		"separator inside": "{\"token_type\":\"Bearer\",\"expires_in\":3600,\"access_token\":\"ab\\u0001cd\"}",
		"not json":         `<html>proxy interception</html>`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			ts := newTestSource(t, func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(w, body)
			})
			if _, err := ts.Token(context.Background()); err == nil {
				t.Fatal("response was accepted")
			}
		})
	}
}

func TestRedirectIsRefused(t *testing.T) {
	ts := newTestSource(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/token", http.StatusFound)
	})
	_, err := ts.Token(context.Background())
	if err == nil {
		t.Fatal("the client followed a redirect from the token endpoint")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewRefusesAnUnsafeTenant(t *testing.T) {
	for _, tenant := range []string{"", "contoso/../evil", "contoso onmicrosoft com", "../../token"} {
		if _, err := New(Options{TenantID: tenant, ClientID: "id", Secret: "s"}); err == nil {
			t.Fatalf("tenant %q was accepted", tenant)
		}
	}
}

func TestTokenAgeReflectsCachedToken(t *testing.T) {
	ts := newTestSource(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, tokenResponse("abc.def", 3600))
	})

	if _, ok := ts.TokenAge(); ok {
		t.Fatal("TokenAge reported a token before one was ever fetched")
	}

	if _, err := ts.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	age, ok := ts.TokenAge()
	if !ok {
		t.Fatal("TokenAge reported no token right after a successful fetch")
	}
	if age < 0 || age > time.Second {
		t.Fatalf("age = %v, want close to 0", age)
	}
}

func TestContextCancellationIsHonoured(t *testing.T) {
	ts := newTestSource(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		fmt.Fprint(w, tokenResponse("late", 3600))
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ts.Token(ctx); err == nil {
		t.Fatal("a cancelled context still produced a token")
	}
}
