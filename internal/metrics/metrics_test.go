// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package metrics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/spool"
)

func TestNewSeedsZeroCountersForConfiguredRoutes(t *testing.T) {
	r := New(nil, nil, []string{"m365", "legacy"}, nil, nil)
	text := r.text()
	for _, want := range []string{
		`smtprelayd_delivered_total{route="legacy"} 0`,
		`smtprelayd_delivered_total{route="m365"} 0`,
		`smtprelayd_bounced_total{route="m365"} 0`,
		`smtprelayd_deferred_total{route="m365"} 0`,
		`smtprelayd_auth_failures_total{route="m365"} 0`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing zero-seeded line %q in:\n%s", want, text)
		}
	}
}

func TestCountersIncrementPerRoute(t *testing.T) {
	r := New(nil, nil, []string{"m365"}, nil, nil)
	r.Delivered("m365")
	r.Delivered("m365")
	r.Bounced("m365")
	r.Deferred("m365")
	r.AuthFailure("m365")

	text := r.text()
	for _, want := range []string{
		`smtprelayd_delivered_total{route="m365"} 2`,
		`smtprelayd_bounced_total{route="m365"} 1`,
		`smtprelayd_deferred_total{route="m365"} 1`,
		`smtprelayd_auth_failures_total{route="m365"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing line %q in:\n%s", want, text)
		}
	}
	if !strings.Contains(text, `smtprelayd_last_delivery_time{route="m365"}`) {
		t.Error("last_delivery_time missing after a delivery")
	}
}

func TestLastDeliveryTimeAbsentBeforeFirstDelivery(t *testing.T) {
	r := New(nil, nil, []string{"m365"}, nil, nil)
	text := r.text()
	if strings.Contains(text, `smtprelayd_last_delivery_time{route="m365"}`) {
		t.Error("last_delivery_time present before any delivery")
	}
}

func TestQueueSizeReflectsSpool(t *testing.T) {
	dir := t.TempDir()
	sp, err := spool.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sp.Enqueue(spool.Envelope{From: "a@example.at", To: []string{"b@example.net"}, Route: "m365"},
		strings.NewReader("x"), 0, 0); err != nil {
		t.Fatal(err)
	}

	r := New(nil, sp, []string{"m365"}, nil, nil)
	text := r.text()
	if !strings.Contains(text, `smtprelayd_queue_size{route="m365",state="queued"} 1`) {
		t.Errorf("queue size not reflected:\n%s", text)
	}
}

func TestStatusSnapshotMatchesCounters(t *testing.T) {
	r := New(nil, nil, []string{"m365", "legacy"}, nil, nil)
	r.Delivered("m365")
	r.Bounced("m365")
	r.Deferred("legacy")

	status := r.Status()
	if len(status) != 2 {
		t.Fatalf("got %d routes, want 2", len(status))
	}
	byRoute := map[string]RouteStatus{}
	for _, st := range status {
		byRoute[st.Route] = st
	}
	if got := byRoute["m365"]; got.Delivered != 1 || got.Bounced != 1 || got.LastDelivery.IsZero() {
		t.Errorf("m365 status = %+v", got)
	}
	if got := byRoute["legacy"]; got.DeferredTotal != 1 || got.HasToken {
		t.Errorf("legacy status = %+v", got)
	}
}

func TestRouteLabelIsEscaped(t *testing.T) {
	r := New(nil, nil, []string{`evil"route`}, nil, nil)
	text := r.text()
	if !strings.Contains(text, `smtprelayd_delivered_total{route="evil\"route"} 0`) {
		t.Errorf("route label not escaped:\n%s", text)
	}
}

func TestServeHTTPRejectsNonGet(t *testing.T) {
	r := New(nil, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestCanaryFailureIsLabeledByNameAndDoesNotTouchRouteMetrics(t *testing.T) {
	r := New(nil, nil, []string{"m365"}, []string{"m365-daily"}, nil)
	r.CanaryFailure("m365-daily")
	r.CanaryFailure("m365-daily")

	text := r.text()
	if !strings.Contains(text, `smtprelayd_canary_failures_total{name="m365-daily"} 2`) {
		t.Errorf("expected a counter labeled by name at 2:\n%s", text)
	}
	if !strings.Contains(text, `smtprelayd_bounced_total{route="m365"} 0`) {
		t.Errorf("canary failures leaked into route-level bounced_total:\n%s", text)
	}
}

func TestCanaryFailureCountsAreIndependentPerName(t *testing.T) {
	r := New(nil, nil, nil, []string{"a", "b"}, nil)
	r.CanaryFailure("a")
	r.CanaryFailure("a")
	r.CanaryFailure("b")

	text := r.text()
	if !strings.Contains(text, `smtprelayd_canary_failures_total{name="a"} 2`) {
		t.Errorf("canary a: want 2:\n%s", text)
	}
	if !strings.Contains(text, `smtprelayd_canary_failures_total{name="b"} 1`) {
		t.Errorf("canary b: want 1:\n%s", text)
	}
}

func TestCanaryDeliveredSetsLastDeliveryTimeNotRouteDelivered(t *testing.T) {
	r := New(nil, nil, []string{"m365"}, []string{"m365-daily"}, nil)
	text := r.text()
	if strings.Contains(text, `smtprelayd_canary_last_delivery_time{name="m365-daily"}`) {
		t.Error("canary_last_delivery_time present before any canary delivery")
	}

	r.CanaryDelivered("m365-daily")
	text = r.text()
	if !strings.Contains(text, `smtprelayd_canary_last_delivery_time{name="m365-daily"}`) {
		t.Errorf("canary_last_delivery_time missing after a canary delivery:\n%s", text)
	}
	if !strings.Contains(text, `smtprelayd_delivered_total{route="m365"} 0`) {
		t.Errorf("canary delivery leaked into route-level delivered_total:\n%s", text)
	}
}

func TestAPIAuthFailureIsUnlabeled(t *testing.T) {
	r := New(nil, nil, []string{"m365"}, nil, nil)
	r.APIAuthFailure()
	r.APIAuthFailure()
	text := r.text()
	if !strings.Contains(text, "smtprelayd_api_auth_failures_total 2") {
		t.Errorf("expected an unlabeled counter at 2:\n%s", text)
	}
}

func TestUptimeAdvances(t *testing.T) {
	r := New(nil, nil, nil, nil, nil)
	if r.Uptime() < 0 {
		t.Fatalf("Uptime is negative: %v", r.Uptime())
	}
}

func TestStatusIncludesOldestQueued(t *testing.T) {
	dir := t.TempDir()
	sp, err := spool.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if _, err := sp.Enqueue(spool.Envelope{From: "a@example.at", To: []string{"b@example.net"}, Route: "m365", Received: old},
		strings.NewReader("x"), 0, time.Hour); err != nil {
		t.Fatal(err)
	}

	r := New(nil, sp, []string{"m365"}, nil, nil)
	status := r.Status()
	if len(status) != 1 || !status[0].OldestQueued.Equal(old) {
		t.Fatalf("got %+v, want OldestQueued %v", status, old)
	}
}

func TestServeHTTPServesText(t *testing.T) {
	r := New(nil, nil, []string{"m365"}, nil, nil)
	r.Delivered("m365")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "smtprelayd_delivered_total") {
		t.Errorf("expected metric names in body:\n%s", rec.Body.String())
	}
}

// A public metrics listener is wrapped in bearer-token authentication. The
// wrapper is tested directly: config.Validate refuses to build such a
// listener without a token, but a validation that is not backed by an
// enforcing handler is the expectation-without-enforcement this fixes.
func TestRequireTokenGuardsTheExposition(t *testing.T) {
	sum := sha256.Sum256([]byte("polling-token"))
	cfg := config.Defaults()
	cfg.Web.Tokens = []config.Token{
		{Name: "checkmk", Scope: "read", SHA256: hex.EncodeToString(sum[:])},
		{Name: "nobody", Scope: "write-only-nonsense", SHA256: strings.Repeat("a", 64)},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	reached := false
	h := requireToken(cfg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }), log)

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"not a bearer scheme", "Basic cG9sbGluZy10b2tlbg==", http.StatusUnauthorized},
		{"valid read token", "Bearer polling-token", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached = false
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if tc.want == http.StatusOK {
				if !reached {
					t.Fatalf("a valid token did not reach the exposition (status %d)", rec.Code)
				}
				return
			}
			if reached {
				t.Fatal("the exposition was reached without a valid token")
			}
			if rec.Code != tc.want {
				t.Fatalf("got status %d, want %d", rec.Code, tc.want)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got == "" {
				t.Error("a 401 must name the scheme it expects")
			}
		})
	}
}

// A loopback listener has no credential to check, so the Host header is the
// only thing separating a local scrape from a browser that was told a name
// resolving to 127.0.0.1. The middleware itself is
// httpx.RequireLoopbackHost, tested there; what is tested here is that Serve
// actually reaches for it when the configured address is a loopback one,
// which is this package's own decision and is what a public listener must
// not get.
func TestLoopbackServeGuardsTheExpositionWithTheHostHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Metrics.Address = ln.Addr().String()
	cfg.Metrics.Path = "/metrics"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, cfg, ln, New(nil, nil, []string{"m365"}, nil, nil), log) }()

	url := "http://" + ln.Addr().String() + "/metrics"
	for host, want := range map[string]int{
		"":                        http.StatusOK, // the address itself
		"localhost":               http.StatusOK,
		"rebind.attacker.example": http.StatusMisdirectedRequest,
		"metrics.internal:9100":   http.StatusMisdirectedRequest,
	} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Host %q: %v", host, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("Host %q: status %d, want %d", host, resp.StatusCode, want)
		}
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Serve returned %v", err)
	}
}

// The gauge Checkmk alerts on. Seconds, not a date, so one expression
// ("< 30*86400") covers both "expiring soon" and "already expired".
func TestExpiryGaugeIsExposed(t *testing.T) {
	now := time.Now()
	cfg := &config.Config{Routes: []config.Route{
		{Name: "m365", Auth: "xoauth2", OAuth2: config.OAuth2{
			TenantID: "t", SecretExpires: now.Add(10 * 24 * time.Hour).Format("2006-01-02"),
		}},
	}}
	body := New(ConfigExpiry(cfg), nil, []string{"m365"}, nil, nil).text()

	if !strings.Contains(body, "# TYPE smtprelayd_expiry_seconds gauge") {
		t.Fatalf("exposition is missing the gauge declaration:\n%s", body)
	}
	line := ""
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "smtprelayd_expiry_seconds{") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no expiry sample:\n%s", body)
	}
	if !strings.Contains(line, `item="oauth2-secret:m365"`) {
		t.Errorf("sample = %q, want it labelled by item", line)
	}
	secs, err := strconv.ParseInt(strings.Fields(line)[1], 10, 64)
	if err != nil {
		t.Fatalf("sample value is not an integer: %q", line)
	}
	// Ten days out, give or take the day boundary the date parses to.
	if secs < 8*86400 || secs > 11*86400 {
		t.Errorf("gauge = %d seconds, want roughly ten days", secs)
	}
}

// Negative once the date has passed, so "already expired" alerts through the
// same expression rather than needing a second one.
func TestExpiryGaugeGoesNegativeAfterTheDate(t *testing.T) {
	cfg := &config.Config{Routes: []config.Route{
		{Name: "m365", Auth: "xoauth2", OAuth2: config.OAuth2{
			TenantID: "t", SecretExpires: time.Now().Add(-5 * 24 * time.Hour).Format("2006-01-02"),
		}},
	}}
	body := New(ConfigExpiry(cfg), nil, []string{"m365"}, nil, nil).text()
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "smtprelayd_expiry_seconds{") {
			if !strings.Contains(l, " -") {
				t.Errorf("an expired item reads %q, want a negative value", l)
			}
			return
		}
	}
	t.Fatalf("no expiry sample:\n%s", body)
}

// A certificate that cannot be read must not simply drop out of the
// exposition: a vanished gauge looks the same as a stopped scrape.
func TestUnreadableCertificateIsExposedAsAnError(t *testing.T) {
	cfg := &config.Config{TLS: config.TLS{CertFile: filepath.Join(t.TempDir(), "absent.crt")}}
	body := New(ConfigExpiry(cfg), nil, nil, nil, nil).text()
	if !strings.Contains(body, "smtprelayd_expiry_read_errors 1") {
		t.Errorf("exposition does not report the unreadable certificate:\n%s", body)
	}
}

// Recipients refused on an otherwise delivered message are the one delivery
// outcome with no counter of its own until now: the message increments
// delivered_total, so an operator watching /metrics saw an unbroken success
// rate while addresses were being refused permanently.
func TestRecipientsRefusedIsCountedPerRoute(t *testing.T) {
	r := New(nil, nil, []string{"m365", "legacy"}, nil, nil)

	// Seeded at zero like every other route counter, so a route that has
	// never hit one is present in the exposition rather than absent.
	if text := r.text(); !strings.Contains(text, `smtprelayd_recipients_refused_total{route="legacy"} 0`) {
		t.Errorf("counter not zero-seeded in:\n%s", text)
	}

	r.RecipientsRefused("m365", 2)
	r.RecipientsRefused("m365", 1)

	text := r.text()
	if !strings.Contains(text, `smtprelayd_recipients_refused_total{route="m365"} 3`) {
		t.Errorf("want 3 refused recipients on m365 in:\n%s", text)
	}
	if !strings.Contains(text, `smtprelayd_recipients_refused_total{route="legacy"} 0`) {
		t.Error("a refusal on one route leaked into another")
	}
	// It must not be mistaken for a delivery failure: the message was
	// delivered to everyone else.
	if !strings.Contains(text, `smtprelayd_bounced_total{route="m365"} 0`) {
		t.Error("a refused recipient was also counted as a bounce")
	}
}

// Status backs the dashboard's route page, so it has to carry the same
// number the exposition does or the two disagree about a route's state.
func TestStatusCarriesRecipientsRefused(t *testing.T) {
	r := New(nil, nil, []string{"m365"}, nil, nil)
	r.RecipientsRefused("m365", 4)
	st := r.Status()
	if len(st) != 1 {
		t.Fatalf("want one route, got %d", len(st))
	}
	if st[0].RecipientsRefused != 4 {
		t.Errorf("Status reports %d refused, want 4", st[0].RecipientsRefused)
	}
}

// The two counters added 2026-09-18 for what used to be invisible: a
// recovered session panic, and a history-store write that failed.
func TestSessionPanicAndJournalFailureCounters(t *testing.T) {
	r := New(nil, nil, nil, nil, nil)
	text := r.text()
	for _, want := range []string{
		"smtprelayd_session_panics_total 0",
		"smtprelayd_journal_write_failures_total 0",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("exposition lacks %q before any event", want)
		}
	}
	r.SessionPanic()
	r.JournalWriteFailure()
	r.JournalWriteFailure()
	text = r.text()
	for _, want := range []string{
		"smtprelayd_session_panics_total 1",
		"smtprelayd_journal_write_failures_total 2",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("exposition lacks %q after the events", want)
		}
	}
}

type fixedAge time.Duration

func (a fixedAge) TokenAge() (time.Duration, bool) { return time.Duration(a), true }

// RegisterTokenAger is how the delivery manager attaches its token sources
// to a registry that was built before it existed; the gauge must appear
// once it has.
func TestRegisterTokenAgerFeedsTheGauge(t *testing.T) {
	r := New(nil, nil, []string{"m365"}, nil, nil)
	if strings.Contains(r.text(), `smtprelayd_oauth_token_age_seconds{route="m365"}`) {
		t.Fatal("token age present before any source was registered")
	}
	r.RegisterTokenAger("m365", fixedAge(90*time.Second))
	if !strings.Contains(r.text(), `smtprelayd_oauth_token_age_seconds{route="m365"} 90`) {
		t.Fatalf("token age missing after registration:\n%s", r.text())
	}
}

// The exposition is a table now (expositionSeries), so the thing worth
// pinning is that every family declares itself properly and that the two
// expiry families stay mutually exclusive: a scraper reads HELP and TYPE, and
// a family that lost one of them, or a gauge that appeared alongside its own
// error gauge, would be a silent misread rather than a failure.
func TestEveryFamilyDeclaresItself(t *testing.T) {
	r := New(nil, nil, []string{"m365"}, []string{"daily"}, nil)
	text := r.text()
	for _, se := range expositionSeries {
		if se.when != nil {
			continue // conditional: covered below
		}
		if !strings.Contains(text, "# HELP "+se.name+" ") {
			t.Errorf("%s has no HELP line", se.name)
		}
		if !strings.Contains(text, "# TYPE "+se.name+" "+se.kind) {
			t.Errorf("%s has no TYPE line", se.name)
		}
		if se.value == nil && se.rows == nil {
			t.Errorf("%s renders no samples at all", se.name)
		}
		if se.value != nil && se.rows != nil {
			t.Errorf("%s sets both value and rows; exactly one is the contract", se.name)
		}
		if se.kind != "counter" && se.kind != "gauge" {
			t.Errorf("%s has type %q", se.name, se.kind)
		}
	}
	if strings.Contains(text, "smtprelayd_expiry_read_errors") {
		t.Error("the read-error gauge is present although the deadlines were readable")
	}
}

// A metric family's name must appear in the Checkmk guide, which is what an
// operator builds alerts from. The table and the document drifted apart once
// already, in the other direction: a documented metric that did not exist.
func TestEveryFamilyIsDocumented(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "guides", "CHECKMK.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, se := range expositionSeries {
		if !strings.Contains(string(doc), se.name) {
			t.Errorf("%s is exposed but absent from docs/guides/CHECKMK.md", se.name)
		}
	}
}
