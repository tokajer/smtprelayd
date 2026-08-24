// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const baseConfig = `
[service]
data_dir = "/tmp/smtprelayd-test"

[[listener]]
name = "smtp"
address = "127.0.0.1:2525"
tls = "none"

[[client]]
name = "printers"
cidr = ["10.10.5.0/24"]
route = "m365"

[[route]]
name = "m365"
default = true
host = "smtp.example"
auth = "none"
`

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "smtprelayd.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadBaseline(t *testing.T) {
	if _, err := Load(write(t, baseConfig)); err != nil {
		t.Fatalf("baseline configuration rejected: %v", err)
	}
}

func TestOpenRelayIsRefused(t *testing.T) {
	body := strings.Replace(baseConfig, `address = "127.0.0.1:2525"`, `address = "0.0.0.0:2525"`, 1)
	body = body[:strings.Index(body, "[[client]]")] + body[strings.Index(body, "[[route]]"):]
	_, err := Load(write(t, body))
	if err == nil {
		t.Fatal("a public listener with no client allowlist was accepted")
	}
	if !strings.Contains(err.Error(), "open relay") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMetricsPathMustStartWithSlash(t *testing.T) {
	body := baseConfig + `
[metrics]
address = "127.0.0.1:9025"
path = "metrics"
enabled = true
`
	_, err := Load(write(t, body))
	if err == nil || !strings.Contains(err.Error(), "metrics.path") {
		t.Fatalf("a metrics path without a leading slash was accepted: %v", err)
	}
}

func TestMetricsDisabledSkipsValidation(t *testing.T) {
	body := baseConfig + `
[metrics]
address = "not a valid address"
path = "also not valid"
enabled = false
`
	if _, err := Load(write(t, body)); err != nil {
		t.Fatalf("disabled metrics section was still validated: %v", err)
	}
}

func TestBounceRequiresSharedSettingsWhenEnabled(t *testing.T) {
	for name, extra := range map[string]string{
		"no sender":     "[bounce]\nnotify = [\"ops@example.at\"]\nnotify_route = \"m365\"\ndigest_minutes = 15\nmax_per_hour = 12\n",
		"no digest":     "[bounce]\nnotify = [\"ops@example.at\"]\nsender = \"bounce@example.at\"\nnotify_route = \"m365\"\ndigest_minutes = 0\nmax_per_hour = 12\n",
		"no cap":        "[bounce]\nnotify = [\"ops@example.at\"]\nsender = \"bounce@example.at\"\nnotify_route = \"m365\"\ndigest_minutes = 15\nmax_per_hour = 0\n",
		"no route":      "[bounce]\nnotify = [\"ops@example.at\"]\nsender = \"bounce@example.at\"\ndigest_minutes = 15\nmax_per_hour = 12\n",
		"unknown route": "[bounce]\nnotify = [\"ops@example.at\"]\nsender = \"bounce@example.at\"\nnotify_route = \"nope\"\ndigest_minutes = 15\nmax_per_hour = 12\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, baseConfig+extra)); err == nil {
				t.Fatalf("%s: incomplete bounce config was accepted", name)
			}
		})
	}
}

func TestBounceFullyConfiguredIsAccepted(t *testing.T) {
	body := baseConfig + `
[bounce]
notify = ["ops@example.at"]
sender = "bounce@example.at"
notify_route = "m365"
digest_minutes = 15
max_per_hour = 12
`
	if _, err := Load(write(t, body)); err != nil {
		t.Fatalf("fully configured bounce section was rejected: %v", err)
	}
}

func TestCanaryRequiresSharedSettingsWhenEnabled(t *testing.T) {
	bounce := "[bounce]\nnotify = [\"ops@example.at\"]\nsender = \"bounce@example.at\"\nnotify_route = \"m365\"\ndigest_minutes = 15\nmax_per_hour = 12\n"
	for name, extra := range map[string]string{
		"no name":               bounce + "[[canary]]\nrecipient = \"ops@example.at\"\nsender = \"canary@example.at\"\nroute = \"m365\"\ninterval_minutes = 1440\n",
		"invalid recipient":     bounce + "[[canary]]\nname = \"m365-daily\"\nrecipient = \"not-an-address\"\nsender = \"canary@example.at\"\nroute = \"m365\"\ninterval_minutes = 1440\n",
		"no sender":             bounce + "[[canary]]\nname = \"m365-daily\"\nrecipient = \"ops@example.at\"\nroute = \"m365\"\ninterval_minutes = 1440\n",
		"invalid sender":        bounce + "[[canary]]\nname = \"m365-daily\"\nrecipient = \"ops@example.at\"\nsender = \"not-an-address\"\nroute = \"m365\"\ninterval_minutes = 1440\n",
		"no route":              bounce + "[[canary]]\nname = \"m365-daily\"\nrecipient = \"ops@example.at\"\nsender = \"canary@example.at\"\ninterval_minutes = 1440\n",
		"unknown route":         bounce + "[[canary]]\nname = \"m365-daily\"\nrecipient = \"ops@example.at\"\nsender = \"canary@example.at\"\nroute = \"nope\"\ninterval_minutes = 1440\n",
		"no interval":           bounce + "[[canary]]\nname = \"m365-daily\"\nrecipient = \"ops@example.at\"\nsender = \"canary@example.at\"\nroute = \"m365\"\ninterval_minutes = 0\n",
		"bounce not configured": "[[canary]]\nname = \"m365-daily\"\nrecipient = \"ops@example.at\"\nsender = \"canary@example.at\"\nroute = \"m365\"\ninterval_minutes = 1440\n",
		"duplicate name": bounce + `[[canary]]
name = "m365-daily"
recipient = "ops@example.at"
sender = "canary@example.at"
route = "m365"
interval_minutes = 1440

[[canary]]
name = "m365-daily"
recipient = "ops2@example.at"
sender = "canary@example.at"
route = "m365"
interval_minutes = 60
`,
		"name collides with a client": bounce + `[[canary]]
name = "printers"
recipient = "ops@example.at"
sender = "canary@example.at"
route = "m365"
interval_minutes = 1440
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, baseConfig+extra)); err == nil {
				t.Fatalf("%s: incomplete canary config was accepted", name)
			}
		})
	}
}

func TestCanaryFullyConfiguredIsAccepted(t *testing.T) {
	body := baseConfig + `
[bounce]
notify = ["ops@example.at"]
sender = "bounce@example.at"
notify_route = "m365"
digest_minutes = 15
max_per_hour = 12

[[canary]]
name = "m365-daily"
recipient = "ops@example.at"
sender = "canary@example.at"
route = "m365"
interval_minutes = 1440
`
	if _, err := Load(write(t, body)); err != nil {
		t.Fatalf("fully configured canary section was rejected: %v", err)
	}
}

func TestMultipleCanariesWithDistinctNamesAreAccepted(t *testing.T) {
	body := baseConfig + `
[[route]]
name = "legacy"
host = "legacy.example"
auth = "none"

[bounce]
notify = ["ops@example.at"]
sender = "bounce@example.at"
notify_route = "m365"
digest_minutes = 15
max_per_hour = 12

[[canary]]
name = "m365-daily"
recipient = "ops@example.at"
sender = "canary@example.at"
route = "m365"
interval_minutes = 1440

[[canary]]
name = "legacy-daily"
recipient = "ops@example.at"
sender = "canary@example.at"
route = "legacy"
interval_minutes = 1440
`
	cfg, err := Load(write(t, body))
	if err != nil {
		t.Fatalf("two distinctly named canaries were rejected: %v", err)
	}
	if len(cfg.Canaries) != 2 {
		t.Fatalf("got %d canaries, want 2", len(cfg.Canaries))
	}
}

func TestClientBounceOverrideOnlyAllowsNotify(t *testing.T) {
	body := strings.Replace(baseConfig, "route = \"m365\"\n", "route = \"m365\"\n\n[client.bounce]\nnotify = [\"printer-ops@example.at\"]\n", 1) + `
[bounce]
sender = "bounce@example.at"
notify_route = "m365"
digest_minutes = 15
max_per_hour = 12
`
	if _, err := Load(write(t, body)); err != nil {
		t.Fatalf("a client overriding only bounce.notify was rejected: %v", err)
	}
}

func TestClientBounceRejectsGlobalOnlyFields(t *testing.T) {
	body := strings.Replace(baseConfig, "route = \"m365\"\n", "route = \"m365\"\n\n[client.bounce]\ndigest_minutes = 5\n", 1) + `
[bounce]
notify = ["ops@example.at"]
sender = "bounce@example.at"
notify_route = "m365"
digest_minutes = 15
max_per_hour = 12
`
	_, err := Load(write(t, body))
	if err == nil || !strings.Contains(err.Error(), "global-only") {
		t.Fatalf("a client setting bounce.digest_minutes was accepted: %v", err)
	}
}

func TestOverlappingCIDRIsRefused(t *testing.T) {
	body := baseConfig + `
[[client]]
name = "overlap"
cidr = ["10.10.5.128/25"]
route = "m365"
`
	_, err := Load(write(t, body))
	if err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("overlapping CIDRs were accepted: %v", err)
	}
}

func TestLiteralSecretIsRefused(t *testing.T) {
	body := baseConfig + `
[[route]]
name = "partner"
host = "mail.partner.example"
auth = "plain"

  [route.credentials]
  username = "relay@example.at"
  password = "hunter2"
`
	_, err := Load(write(t, body))
	if err == nil || !strings.Contains(err.Error(), "never a literal value") {
		t.Fatalf("a plaintext password in the configuration was accepted: %v", err)
	}
}

func TestSecretNeverFormats(t *testing.T) {
	t.Setenv("SMTPRELAYD_TEST_SECRET", "topsecret")
	body := baseConfig + `
[[route]]
name = "partner"
host = "mail.partner.example"
auth = "login"

  [route.credentials]
  username = "relay@example.at"
  password = "${SMTPRELAYD_TEST_SECRET}"
`
	cfg, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := cfg.Route("partner")
	if r.Credentials.Password.Value() != "topsecret" {
		t.Fatal("secret was not resolved from the environment")
	}
	for _, rendered := range []string{
		strings.TrimSpace(r.Credentials.Password.String()),
		fmt.Sprintf("%v", r.Credentials.Password),
		fmt.Sprintf("%s", r.Credentials.Password),
		fmt.Sprintf("%#v", r.Credentials.Password),
		fmt.Sprintf("%v", r.Credentials),
	} {
		if strings.Contains(rendered, "topsecret") {
			t.Fatalf("secret leaked through formatting: %s", rendered)
		}
	}
}

func TestUnknownKeyIsRefused(t *testing.T) {
	body := baseConfig + "\n[queue]\ninsecure_skip_verify = true\n"
	if _, err := Load(write(t, body)); err == nil {
		t.Fatal("an unknown key was silently ignored")
	}
}

func TestOutboundTLSCannotBeWeakened(t *testing.T) {
	body := strings.Replace(baseConfig, `auth = "none"`, "auth = \"none\"\nmin_tls = \"1.0\"", 1)
	if _, err := Load(write(t, body)); err == nil {
		t.Fatal("an outbound TLS minimum below 1.2 was accepted")
	}
}

func TestCleartextRouteIsAccepted(t *testing.T) {
	body := strings.Replace(baseConfig, `auth = "none"`, "auth = \"none\"\ntls = \"none\"", 1)
	cfg, err := Load(write(t, body))
	if err != nil {
		t.Fatalf("tls none was rejected: %v", err)
	}
	if cfg.Routes[0].TLS != "none" {
		t.Fatalf("tls none was rewritten to %q", cfg.Routes[0].TLS)
	}
	if cfg.Routes[0].MinTLS != "" {
		t.Fatalf("min_tls defaulted to %q on a route with no handshake", cfg.Routes[0].MinTLS)
	}
}

func TestCleartextRouteRefusesAuth(t *testing.T) {
	for _, auth := range []string{"plain", "login", "xoauth2"} {
		body := strings.Replace(baseConfig, `auth = "none"`,
			fmt.Sprintf("auth = %q\ntls = \"none\"", auth), 1)
		if _, err := Load(write(t, body)); err == nil {
			t.Fatalf("auth %s was accepted on a cleartext route", auth)
		}
	}
}

func TestCleartextRouteRefusesHandshakeSettings(t *testing.T) {
	for _, key := range []string{`min_tls = "1.2"`, `ca_pin = "ab"`} {
		body := strings.Replace(baseConfig, `auth = "none"`,
			"auth = \"none\"\ntls = \"none\"\n"+key, 1)
		if _, err := Load(write(t, body)); err == nil {
			t.Fatalf("%s was silently ignored on a cleartext route", key)
		}
	}
}

// The dashboard has no authentication of its own, so a public bind is
// refused outright rather than served with a certificate and no credential.
func TestWebAddressBeyondLoopbackIsRefused(t *testing.T) {
	body := baseConfig + `
[web]
enabled = true
address = "0.0.0.0:8443"
`
	if e := loadErr(t, body); !strings.Contains(e, "no authentication") {
		t.Fatalf("unexpected error: %s", e)
	}

	ok := baseConfig + `
[web]
enabled = true
address = "127.0.0.1:8025"
`
	if _, err := Load(write(t, ok)); err != nil {
		t.Fatalf("a loopback dashboard was rejected: %v", err)
	}
}

// The metrics endpoint may bind publicly, because a monitoring system can
// present a token — but only with a token that exists and only over TLS.
func TestMetricsBeyondLoopbackNeedsTokenAndTLS(t *testing.T) {
	noToken := baseConfig + `
[metrics]
enabled = true
address = "0.0.0.0:9025"
path = "/metrics"
`
	e := loadErr(t, noToken)
	if !strings.Contains(e, "read scope") {
		t.Fatalf("a public metrics listener with no token was not refused for that reason: %s", e)
	}
	if !strings.Contains(e, "TLS certificate") {
		t.Fatalf("a public metrics listener with no certificate was not refused for that reason: %s", e)
	}

	// An admin-scope token satisfies read, so it must not be reported as
	// missing; only the certificate should still be.
	adminToken := noToken + `
[[web.token]]
name = "ops"
scope = "admin"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
`
	e = loadErr(t, adminToken)
	if strings.Contains(e, "read scope") {
		t.Fatalf("an admin token was not accepted as read-capable: %s", e)
	}

	// Loopback stays open and needs neither, per the Checkmk decision.
	loopback := baseConfig + `
[metrics]
enabled = true
address = "127.0.0.1:9025"
path = "/metrics"
`
	if _, err := Load(write(t, loopback)); err != nil {
		t.Fatalf("a loopback metrics listener was rejected: %v", err)
	}
}

func TestMatchTokenIsScopeAware(t *testing.T) {
	sum := sha256.Sum256([]byte("s3cr3t"))
	c := Defaults()
	c.Web.Tokens = []Token{{Name: "checkmk", Scope: "read", SHA256: hex.EncodeToString(sum[:])}}

	got, ok := c.MatchToken("s3cr3t")
	if !ok || got.Name != "checkmk" {
		t.Fatalf("a valid token did not match: %+v %v", got, ok)
	}
	if _, ok := c.MatchToken("wrong"); ok {
		t.Fatal("a wrong token matched")
	}
	if _, ok := c.MatchToken(""); ok {
		t.Fatal("an empty token matched")
	}
	if !c.HasReadableToken() {
		t.Fatal("a read token was not recognised as read-capable")
	}
	c.Web.Tokens[0].Scope = "admin"
	if !c.HasReadableToken() {
		t.Fatal("an admin token must satisfy read")
	}
}

func TestThemeColorMustBeHex(t *testing.T) {
	// Every rejected value is one that would otherwise end up verbatim
	// inside a CSS custom property declaration: the first two close the
	// declaration and open a rule of their own, the third and fourth are
	// syntaxes that can name a URL, the last is simply not a colour.
	for _, bad := range []string{
		`#fff; } body { display: none`,
		`red; --x: url(http://evil.example/x)`,
		`url(http://evil.example/x)`,
		`var(--accent)`,
		`rebeccapurple`,
		`#ff`,
		`#1234567`,
		`#12345g`,
	} {
		body := baseConfig + "\n[web]\nenabled = true\n[web.theme]\naccent = " + fmt.Sprintf("%q", bad) + "\n"
		_, err := Load(write(t, body))
		if err == nil || !strings.Contains(err.Error(), "web.theme.accent") {
			t.Errorf("theme colour %q accepted: %v", bad, err)
		}
	}
}

func TestThemeAcceptsHexColorsAndModes(t *testing.T) {
	body := baseConfig + `
[web]
enabled = true

[web.theme]
mode       = "dark"
accent     = "#7C4DFF"
background = "#101"
danger     = "#b02a2a"
`
	cfg, err := Load(write(t, body))
	if err != nil {
		t.Fatalf("valid theme rejected: %v", err)
	}
	if got := cfg.Web.Theme.Colors(); len(got) != 3 || got["--accent"] != "#7C4DFF" {
		t.Fatalf("Colors() = %v", got)
	}
}

func TestThemeModeIsCheckedAgainstAFixedSet(t *testing.T) {
	body := baseConfig + "\n[web]\nenabled = true\n[web.theme]\nmode = \"neon\"\n"
	_, err := Load(write(t, body))
	if err == nil || !strings.Contains(err.Error(), "web.theme.mode") {
		t.Fatalf("unknown theme mode accepted: %v", err)
	}
}

// Everything else interpolated into the Received: header has been proved free
// of CR, LF and NUL by the code that produced it. The configured hostname goes
// into that header and into the 220 banner, and had never been checked.
func TestHostnameRejectsHeaderSplittingBytes(t *testing.T) {
	for _, bad := range []string{
		"relay.example\r\nX-Injected: yes",
		"relay.example\nX-Injected: yes",
		"relay.example\x00",
	} {
		body := strings.Replace(baseConfig,
			`data_dir = "/tmp/smtprelayd-test"`,
			`data_dir = "/tmp/smtprelayd-test"`+"\nhostname = "+fmt.Sprintf("%q", bad), 1)
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("hostname %q was accepted", bad)
		} else if !strings.Contains(err.Error(), "service.hostname") {
			t.Errorf("hostname %q rejected for the wrong reason: %v", bad, err)
		}
	}
}

// A truncated pin decodes cleanly and then fails every comparison at delivery
// time, blaming the smarthost's certificate for what is a typo here.
func TestCAPinMustBeAFullSHA256(t *testing.T) {
	full := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		pin  string
		want bool
	}{
		{full, true},
		{strings.ToUpper(full), true},
		{strings.Repeat("ab:", 31) + "ab", true}, // colon-separated is accepted
		{strings.Repeat("ab", 16), false},        // truncated to SHA-128 length
		{strings.Repeat("ab", 48), false},        // SHA-384 by mistake
		{"nothex" + strings.Repeat("a", 58), false},
	} {
		body := baseConfig + "ca_pin = " + fmt.Sprintf("%q", tc.pin) + "\n"
		_, err := Load(write(t, body))
		if tc.want && err != nil {
			t.Errorf("ca_pin %q was rejected: %v", tc.pin, err)
		}
		if !tc.want && err == nil {
			t.Errorf("ca_pin %q was accepted", tc.pin)
		}
	}
}

// rateLimiter.allow, connCounter.acquire and Spool.SetQuota all read a limit
// of zero or less as "unlimited", so a mistyped minus sign switched the
// control off instead of failing startup.
func TestNegativeLimitsAreRejectedInsteadOfMeaningUnlimited(t *testing.T) {
	cases := map[string]string{
		"client.rate_limit_per_min": strings.Replace(baseConfig,
			`route = "m365"`, "route = \"m365\"\nrate_limit_per_min = -1", 1),
		"client.max_connections": strings.Replace(baseConfig,
			`route = "m365"`, "route = \"m365\"\nmax_connections = -5", 1),
		"route.rate_limit_per_min": baseConfig + "rate_limit_per_min = -30\n",
		"limits.spool_max_gb":      baseConfig + "\n[limits]\nspool_max_gb = -1\n",
		"limits.spool_max_gb overflow": baseConfig + "\n[limits]\nspool_max_gb = " +
			fmt.Sprint(int64(1)<<40) + "\n",
		"queue.failed_retention_hours": baseConfig + "\n[queue]\nfailed_retention_hours = -1\n",
	}
	for name, body := range cases {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: a negative or overflowing value was accepted", name)
		}
	}

	// Zero must stay legal: it is the documented way to say "no limit".
	for name, body := range map[string]string{
		"rate_limit_per_min = 0":     baseConfig + "rate_limit_per_min = 0\n",
		"failed_retention_hours = 0": baseConfig + "\n[queue]\nfailed_retention_hours = 0\n",
		"spool_max_gb = 0":           baseConfig + "\n[limits]\nspool_max_gb = 0\n",
	} {
		if _, err := Load(write(t, body)); err != nil {
			t.Errorf("%s was rejected: %v", name, err)
		}
	}
}

// bounce.sender and every notify entry reach a From:/To: line through
// fmt.Fprintf, so a CR or LF in one splits the digest's header block.
func TestBounceAddressesAreValidated(t *testing.T) {
	const route = "\n[bounce]\nnotify_route = \"m365\"\ndigest_minutes = 15\nmax_per_hour = 12\n"
	for name, section := range map[string]string{
		"CRLF in sender":           route + "sender = \"postmaster@example.at\\r\\nBcc: x@evil.example\"\nnotify = [\"ops@example.at\"]\n",
		"LF in a notify entry":     route + "sender = \"postmaster@example.at\"\nnotify = [\"ops@example.at\\nBcc: x@evil.example\"]\n",
		"notify is not an address": route + "sender = \"postmaster@example.at\"\nnotify = [\"not-an-address\"]\n",
		"sender is not an address": route + "sender = \"postmaster\"\nnotify = [\"ops@example.at\"]\n",
	} {
		if _, err := Load(write(t, baseConfig+section)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	good := route + "sender = \"postmaster@example.at\"\nnotify = [\"ops@example.at\"]\n"
	if _, err := Load(write(t, baseConfig+good)); err != nil {
		t.Fatalf("a valid bounce configuration was rejected: %v", err)
	}
}
