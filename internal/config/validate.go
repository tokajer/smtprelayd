// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"
)

// DefaultScope is the Exchange Online resource scope for the client
// credentials flow. Microsoft 365 rejects anything else for SMTP submission.
const DefaultScope = "https://outlook.office365.com/.default"

// secretExpiresLayout is the date format of oauth2.secret_expires.
const secretExpiresLayout = "2006-01-02" //#nosec G101 -- a date layout, not a credential

// tenantID bounds what may be interpolated into the token endpoint URL. A
// tenant is a GUID or a domain name; anything that could add or traverse a
// path segment is rejected before it reaches net/url.
var tenantID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`)

// ValidTenantID reports whether s is safe to place in the token endpoint path.
func ValidTenantID(s string) bool { return tenantID.MatchString(s) }

// maxExpiryWarnDays bounds expiry.warn_days at ten years.
const maxExpiryWarnDays = 3650

// maxSpoolGB is an exabyte, chosen only so that the gigabytes-to-bytes
// multiplication in Spool.SetQuota cannot overflow int64 and land back on
// "no quota". No filesystem this reaches is anywhere near it.
const maxSpoolGB = 1 << 30

// Per-element defaults, named so that normalize and the checks that accept
// these values cannot drift apart.
const (
	defaultListenerTLS      = "none"
	defaultRewriteMode      = "off"
	defaultRoutePort        = 587
	defaultRouteTLS         = "starttls"
	defaultRouteConcurrency = 4
)

// owned pairs a CIDR prefix with the client or route name that claims it, so
// that an overlap error can name the other owner.
type owned struct {
	prefix netip.Prefix
	owner  string
}

// validator accumulates every problem found in one configuration rather than
// stopping at the first, so an operator fixing a file sees the whole list.
// The cross-section fields exist because some checks depend on an earlier
// section's result: a canary name may not collide with a client name, a
// bounce route must name a route that exists.
type validator struct {
	c    *Config
	errs []string

	// Set by listeners, read by tls and clients.
	needsCert bool
	anyPublic bool

	// Set by clients, read by canaries.
	clientNames map[string]bool

	// Set by routes, read by clientRoutes, bounce and canaries.
	routeNames map[string]bool
	defaults   int
}

func (v *validator) add(format string, a ...any) {
	v.errs = append(v.errs, fmt.Sprintf(format, a...))
}

// normalize applies the per-element defaults that Defaults cannot: they
// belong to slice entries that do not exist until the file has been decoded.
// It runs before validation so that the checks below read one settled value
// rather than "the configured value, or the default if empty". It holds
// exactly the defaults that are unconditional and independent of any other
// field on the element. Two look like they belong here but do not:
// route.oauth2.scope is set only when the route actually uses OAuth2, so
// setting it unconditionally would populate the field on routes that never
// read it; the domain lower-casing in routes() is interleaved with
// duplicate-domain detection in the same loop and cannot be hoisted without
// duplicating that loop.
func (c *Config) normalize() {
	for i := range c.Listeners {
		if c.Listeners[i].TLS == "" {
			c.Listeners[i].TLS = defaultListenerTLS
		}
	}
	for i := range c.Clients {
		if c.Clients[i].Rewrite.Mode == "" {
			c.Clients[i].Rewrite.Mode = defaultRewriteMode
		}
	}
	for i := range c.Routes {
		if c.Routes[i].Port == 0 {
			c.Routes[i].Port = defaultRoutePort
		}
		if c.Routes[i].TLS == "" {
			c.Routes[i].TLS = defaultRouteTLS
		}
		if c.Routes[i].MaxConcurrent <= 0 {
			c.Routes[i].MaxConcurrent = defaultRouteConcurrency
		}
	}
}

// newValidator normalizes the configuration before any check reads it: the
// section methods assume the per-element defaults are already settled, and
// reaching one without that produces errors about values the operator never
// wrote.
func newValidator(c *Config) *validator {
	c.normalize()
	return &validator{c: c, clientNames: map[string]bool{}, routeNames: map[string]bool{}}
}

// Validate enforces every rule from docs/guides/SECURITY.md that can be decided
// without touching the network. Ambiguity is an error, never a warning.
func (c *Config) Validate() error {
	v := newValidator(c)
	v.service()
	v.listeners()
	v.tls()
	v.clients()
	v.routes()
	v.clientRoutes()
	v.queue()
	v.web()
	v.metrics()
	v.history()
	v.bounce()
	v.canaries()
	v.limits()
	if len(v.errs) > 0 {
		return fmt.Errorf("config %s:\n  - %s", c.Path, strings.Join(v.errs, "\n  - "))
	}
	return nil
}

// service checks the [service] section.
func (v *validator) service() {
	if v.c.Service.DataDir == "" {
		v.add("service.data_dir is required")
	}
	if _, err := ParseLevel(v.c.Service.LogLevel); err != nil {
		v.add("service.log_level: %v", err)
	}
	if _, err := ParseTimezone(v.c.Service.Timezone); err != nil {
		v.add("service.timezone: %v", err)
	}
	// The hostname default is resolved here, not in normalize, because
	// os.Hostname can fail: the failure becomes a validation error, so this
	// is not a pure element-level default the way the TLS, rewrite mode and
	// port defaults are.
	if v.c.Service.Hostname == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			v.add("service.hostname is required (host name could not be determined)")
		} else {
			v.c.Service.Hostname = h
		}
	}
	// The hostname is interpolated into the Received: header and into the 220
	// banner. Every other value that reaches that header has been proved free
	// of CR, LF and NUL by the code that produced it; this one comes straight
	// from the configuration file and had not been.
	if strings.ContainsAny(v.c.Service.Hostname, "\r\n\x00") {
		v.add("service.hostname must not contain CR, LF or NUL: it is written into the Received header")
	}

	// The log file is the one configuration string that becomes a path by
	// being joined to another, so it is the one that has to be proved
	// incapable of naming a location outside the data directory. A daemon
	// that runs privileged enough to bind port 25 must not be steerable into
	// creating or appending to a file anywhere on the host.
	if v.c.Service.DataDir != "" {
		if _, err := LogPath(v.c.Service.DataDir, v.c.Log.File); err != nil {
			v.add("%v", err)
		}
	}
}

// listeners checks the [[listener]] section, recording whether any listener
// needs a certificate or binds a non-loopback address, for tls and clients
// to read.
func (v *validator) listeners() {
	if len(v.c.Listeners) == 0 {
		v.add("at least one [[listener]] is required")
	}
	names := map[string]bool{}
	for i, l := range v.c.Listeners {
		where := fmt.Sprintf("listener[%d] %q", i, l.Name)
		if !ValidName(l.Name) {
			v.add("%s: name must be 1 to %d printable ASCII characters without a quote or backslash", where, maxNameLen)
		} else if names[l.Name] {
			v.add("%s: duplicate listener name", where)
		}
		names[l.Name] = true

		host, _, err := net.SplitHostPort(l.Address)
		if err != nil {
			v.add("%s: address %q: %v", where, l.Address, err)
		} else if !isLoopbackHost(host) {
			v.anyPublic = true
		}
		switch l.TLS {
		case defaultListenerTLS, "starttls", "implicit":
		default:
			v.add("%s: tls must be none, starttls or implicit", where)
		}
		if v.c.Listeners[i].TLS != "none" {
			v.needsCert = true
		}
		if l.RequireTLS && v.c.Listeners[i].TLS == "none" {
			v.add("%s: require_tls is set but tls is none", where)
		}
		if l.MinTLS != "" {
			if _, err := ParseTLSVersion(l.MinTLS); err != nil {
				v.add("%s: min_tls: %v", where, err)
			}
		}
	}
}

// tls checks the [tls] certificate pair, but only when some listener needs one.
func (v *validator) tls() {
	if v.needsCert {
		if v.c.TLS.CertFile == "" || v.c.TLS.KeyFile == "" {
			v.add("[tls] cert_file and key_file are required when a listener uses TLS")
		} else if _, err := tls.LoadX509KeyPair(v.c.TLS.CertFile, v.c.TLS.KeyFile); err != nil {
			v.add("[tls]: %v", err)
		}
	}
}

// clients checks the fail-closed [[client]] section, recording the accepted
// names for canaries to check against later.
func (v *validator) clients() {
	// Fail closed. An empty allowlist is a configuration error and never an
	// implicit "allow all" -- an open relay is the one failure that cannot be
	// recovered from cheaply.
	if len(v.c.Clients) == 0 {
		if v.anyPublic {
			v.add("no [[client]] is defined but a listener binds a non-loopback address: this would be an open relay")
		} else {
			v.add("at least one [[client]] is required")
		}
	}

	var prefixes []owned
	for i := range v.c.Clients {
		cl := &v.c.Clients[i]
		where := fmt.Sprintf("client[%d] %q", i, cl.Name)
		if !ValidName(cl.Name) {
			v.add("%s: name must be 1 to %d printable ASCII characters without a quote or backslash", where, maxNameLen)
		} else if v.clientNames[cl.Name] {
			v.add("%s: duplicate client name", where)
		}
		v.clientNames[cl.Name] = true

		if len(cl.CIDR) == 0 {
			v.add("%s: at least one cidr is required", where)
		}
		for _, s := range cl.CIDR {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				v.add("%s: cidr %q: %v", where, s, err)
				continue
			}
			if p.Addr() != p.Masked().Addr() {
				v.add("%s: cidr %q has host bits set, use %s", where, s, p.Masked())
				continue
			}
			for _, o := range prefixes {
				if o.prefix.Overlaps(p) {
					v.add("%s: cidr %s overlaps %s of client %q: matching would be ambiguous",
						where, p, o.prefix, o.owner)
				}
			}
			prefixes = append(prefixes, owned{prefix: p, owner: cl.Name})
		}

		switch cl.Rewrite.Mode {
		case defaultRewriteMode:
		case "force", "if_unauthorized":
			switch {
			case cl.Rewrite.EnvelopeFrom == "":
				v.add("%s: rewrite.envelope_from is required for mode %s", where, cl.Rewrite.Mode)
			case !ValidAddress(cl.Rewrite.EnvelopeFrom):
				v.add("%s: rewrite.envelope_from %q is not a valid address", where, cl.Rewrite.EnvelopeFrom)
			}
			// An empty allowlist would make if_unauthorized behave exactly
			// like force while reading as if it were selective.
			if cl.Rewrite.Mode == "if_unauthorized" && len(cl.Rewrite.AllowedSenders) == 0 {
				v.add("%s: rewrite.mode if_unauthorized requires at least one allowed_senders entry", where)
			}
			if hf := strings.TrimSpace(cl.Rewrite.HeaderFrom); hf != "" && hf != "keep" {
				_, addr, ok := SplitMailbox(hf)
				switch {
				case !ok:
					v.add("%s: rewrite.header_from must be keep, an address, or "+
						"a printable ASCII display name followed by <address>", where)
				case DomainOf(addr) != DomainOf(cl.Rewrite.EnvelopeFrom):
					// SPF checks the envelope and DMARC checks the header, so
					// a split between the two domains fails alignment at the
					// smarthost and is never what the operator wanted.
					v.add("%s: rewrite.header_from domain %q does not match rewrite.envelope_from domain %q",
						where, DomainOf(addr), DomainOf(cl.Rewrite.EnvelopeFrom))
				}
			}
		default:
			v.add("%s: rewrite.mode must be off, if_unauthorized or force", where)
		}
		for j, p := range cl.Rewrite.AllowedSenders {
			if !ValidSenderPattern(p) {
				v.add("%s: rewrite.allowed_senders[%d] %q must be an address or *@domain", where, j, p)
			}
		}
		switch rt := strings.TrimSpace(cl.Rewrite.ReplyTo); {
		case rt == "" || rt == "preserve" || rt == "drop":
		case strings.HasPrefix(rt, "fixed:"):
			if !ValidAddress(strings.TrimSpace(strings.TrimPrefix(rt, "fixed:"))) {
				v.add("%s: rewrite.reply_to fixed address is not valid", where)
			}
		default:
			v.add("%s: rewrite.reply_to must be preserve, drop or fixed:<address>", where)
		}
		// rateLimiter.allow and connCounter.acquire both read a limit of zero
		// or less as "unlimited", so a mistyped minus sign switches the
		// control off instead of failing startup -- the same "looks
		// configured but does nothing" shape strict TOML decoding exists to
		// prevent, one layer below where decoding can see it.
		if cl.MaxMessageMB < 0 || cl.MaxRecipients < 0 || cl.RateLimitPerMin < 0 || cl.MaxConnections < 0 {
			v.add("%s: max_message_mb, max_recipients, rate_limit_per_min and max_connections must not be negative "+
				"(0 means unlimited)", where)
		}
	}
}

// routes checks the [[route]] section. It records the accepted route names
// and the count of routes marked default, for clientRoutes, bounce and
// canaries to check against.
func (v *validator) routes() {
	domainOwner := map[string]string{}
	var sourcePrefixes []owned
	for i := range v.c.Routes {
		r := &v.c.Routes[i]
		where := fmt.Sprintf("route[%d] %q", i, r.Name)
		if !ValidName(r.Name) {
			v.add("%s: name must be 1 to %d printable ASCII characters without a quote or backslash", where, maxNameLen)
		} else if v.routeNames[r.Name] {
			v.add("%s: duplicate route name", where)
		}
		v.routeNames[r.Name] = true
		if r.Default {
			v.defaults++
		}
		if r.Host == "" {
			v.add("%s: host is required", where)
		}
		if r.Port < 1 || r.Port > 65535 {
			v.add("%s: port %d is out of range", where, r.Port)
		}
		switch r.TLS {
		case defaultRouteTLS, "implicit":
		case "none":
			// Cleartext delivery exists for smarthosts on a segment the
			// operator controls end to end. It is never a fallback: a route
			// asking for TLS that cannot negotiate it defers, it does not
			// downgrade. Settings that only describe a handshake are an
			// error here rather than silently ignored, because a route
			// carrying min_tls reads as if it were still encrypted.
			if r.MinTLS != "" {
				v.add("%s: min_tls is meaningless with tls none, remove it", where)
			}
			if r.CAPin != "" {
				v.add("%s: ca_pin is meaningless with tls none, remove it", where)
			}
		default:
			v.add("%s: tls must be none, starttls or implicit", where)
		}
		if r.TLS == "none" {
			// Credentials are never put on an unprotected wire. A bearer
			// token read off it grants mailbox access far beyond this relay,
			// and PLAIN hands over the password outright; net/smtp refuses
			// PlainAuth on an unencrypted connection anyway, so accepting it
			// here would only turn a startup error into a delivery failure.
			if r.Auth != "" && r.Auth != "none" {
				v.add("%s: auth %s requires tls starttls or implicit; "+
					"tls none supports auth none only", where, r.Auth)
			}
		} else if r.MinTLS == "" {
			r.MinTLS = "1.2"
		} else if ver, err := ParseTLSVersion(r.MinTLS); err != nil {
			v.add("%s: min_tls: %v", where, err)
		} else if ver < tls.VersionTLS12 {
			v.add("%s: min_tls must be at least 1.2 for outbound connections", where)
		}
		switch r.Auth {
		case "none":
		case "plain", "login":
			if r.Credentials.Username == "" || r.Credentials.Password.Empty() {
				v.add("%s: auth %s requires credentials.username and credentials.password", where, r.Auth)
			}
		case "xoauth2":
			o := r.OAuth2
			switch {
			case o.TenantID == "" || o.ClientID == "" || o.ClientSecret.Empty() || o.Mailbox == "":
				v.add("%s: auth xoauth2 requires oauth2 tenant_id, client_id, client_secret and mailbox", where)
			default:
				if !ValidTenantID(o.TenantID) {
					v.add("%s: oauth2.tenant_id must be a tenant GUID or domain name", where)
				}
				// The mailbox is concatenated into the XOAUTH2 payload around
				// \x01 separators, so anything outside printable ASCII could
				// forge a field.
				if !printableASCII(o.Mailbox) || !strings.Contains(o.Mailbox, "@") {
					v.add("%s: oauth2.mailbox must be an ASCII email address", where)
				}
				if o.Scope == "" {
					r.OAuth2.Scope = DefaultScope
				} else if !strings.HasPrefix(o.Scope, "https://") || !strings.HasSuffix(o.Scope, "/.default") {
					v.add("%s: oauth2.scope must be an https resource scope ending in /.default", where)
				}
				if o.SecretExpires != "" {
					if _, err := time.Parse(secretExpiresLayout, o.SecretExpires); err != nil {
						v.add("%s: oauth2.secret_expires must be YYYY-MM-DD", where)
					}
				}
			}
		case "":
			v.add("%s: auth is required (none, plain, login or xoauth2)", where)
		default:
			v.add("%s: auth must be none, plain, login or xoauth2", where)
		}
		if r.CAPin != "" {
			// A truncated pin decodes cleanly and then never matches the
			// full-length comparison in smarthost, so the route fails closed
			// -- but at delivery time, with an error blaming the smarthost's
			// certificate for what is a typo in the configuration.
			b, err := hex.DecodeString(strings.ReplaceAll(r.CAPin, ":", ""))
			switch {
			case err != nil:
				v.add("%s: ca_pin must be a hex SHA-256 fingerprint", where)
			case len(b) != sha256.Size:
				v.add("%s: ca_pin must be a SHA-256 fingerprint of %d hex characters, got %d",
					where, sha256.Size*2, len(b)*2)
			}
		}
		if r.RateLimitPerMin < 0 {
			v.add("%s: rate_limit_per_min must not be negative (0 means unpaced)", where)
		}

		// Recipient domains take precedence over the route named by the
		// client, so a domain claimed twice would silently pick one of them.
		for j, d := range r.Domains {
			dl := strings.ToLower(strings.TrimSpace(d))
			if !ValidDomain(dl) {
				v.add("%s: domains[%d] %q is not a valid domain name", where, j, d)
				continue
			}
			if owner, dup := domainOwner[dl]; dup {
				v.add("%s: domain %q is already routed by route %q", where, dl, owner)
				continue
			}
			domainOwner[dl] = r.Name
			r.Domains[j] = dl
		}

		// Source networks may deliberately overlap a client CIDR -- that is
		// how a site-wide route coexists with a per-device one -- but two
		// routes claiming the same network would be ambiguous.
		for j, src := range r.Sources {
			p, err := netip.ParsePrefix(src)
			if err != nil {
				v.add("%s: sources[%d] %q: %v", where, j, src, err)
				continue
			}
			if p.Addr() != p.Masked().Addr() {
				v.add("%s: sources[%d] %q has host bits set, use %s", where, j, src, p.Masked())
				continue
			}
			for _, o := range sourcePrefixes {
				if o.prefix.Overlaps(p) {
					v.add("%s: sources %s overlaps %s of route %q: matching would be ambiguous",
						where, p, o.prefix, o.owner)
				}
			}
			sourcePrefixes = append(sourcePrefixes, owned{prefix: p, owner: r.Name})
		}
	}
	if len(v.c.Routes) == 0 {
		v.add("at least one [[route]] is required")
	}
	if v.defaults > 1 {
		v.add("more than one route is marked default")
	}
}

// clientRoutes checks that every client either names a route that exists or
// can fall back to it.
func (v *validator) clientRoutes() {
	for _, cl := range v.c.Clients {
		if cl.Route == "" {
			if v.defaults == 0 {
				v.add("client %q has no route and no default route exists", cl.Name)
			}
			continue
		}
		if !v.routeNames[cl.Route] {
			v.add("client %q references unknown route %q", cl.Name, cl.Route)
		}
	}
}

// queue checks the [queue] section.
func (v *validator) queue() {
	if len(v.c.Queue.RetryScheduleMin) == 0 {
		v.add("queue.retry_schedule_min must not be empty")
	}
	for _, m := range v.c.Queue.RetryScheduleMin {
		if m <= 0 {
			v.add("queue.retry_schedule_min must contain positive values")
		}
	}
	if v.c.Queue.MaxLifetimeHours <= 0 {
		v.add("queue.max_lifetime_hours must be positive")
	}
	if v.c.Queue.FailedRetentionHours < 0 {
		v.add("queue.failed_retention_hours must not be negative (0 keeps failed messages forever)")
	}
}

// web checks the [web] section.
func (v *validator) web() {
	if v.c.Web.Enabled {
		if host, _, err := net.SplitHostPort(v.c.Web.Address); err != nil {
			v.add("web.address %q: %v", v.c.Web.Address, err)
		} else if !isLoopbackHost(host) {
			// The dashboard has no authentication of its own. Its
			// requeue and delete forms are protected by a CSRF token
			// fetched from the page itself, which stops another site
			// from driving them but is not a credential: anyone who can
			// reach the page can do everything on it. Bearer tokens
			// cannot close this — the process holds only their SHA-256
			// digests, so the dashboard cannot present one for itself.
			//
			// Until a login exists, loopback *is* the authentication,
			// which is what internal/web/csrf.go already assumes. A
			// public bind is therefore refused rather than served with a
			// TLS certificate and no credential, which is what this
			// check required until 2026-08-11.
			v.add("web.address %q binds beyond loopback and the dashboard has no authentication; "+
				"bind it to 127.0.0.1 and reach it through an SSH tunnel or a reverse proxy that authenticates",
				v.c.Web.Address)
		}
	}
	// Validated whether or not the dashboard is enabled: a rejected colour is
	// a typo the operator wants to hear about now, not the first time the
	// dashboard is switched on.
	switch v.c.Web.Theme.Mode {
	case "", "auto", "light", "dark":
	default:
		v.add("web.theme.mode %q: must be auto, light or dark", v.c.Web.Theme.Mode)
	}
	th := v.c.Web.Theme
	for _, f := range []struct{ key, value string }{
		{"accent", th.Accent}, {"accent_text", th.AccentText}, {"background", th.Background},
		{"surface", th.Surface}, {"border", th.Border}, {"text", th.Text},
		{"muted", th.Muted}, {"ok", th.OK}, {"warn", th.Warn}, {"danger", th.Danger},
	} {
		if f.value != "" && !IsHexColor(f.value) {
			v.add("web.theme.%s %q: must be a hex colour such as #2f5fa8 or #fff", f.key, f.value)
		}
	}
	for i, t := range v.c.Web.Tokens {
		if !ValidName(t.Name) {
			v.add("web.token[%d]: name must be 1 to %d printable ASCII characters without a quote or backslash", i, maxNameLen)
		}
		if t.Scope != "read" && t.Scope != "admin" {
			v.add("web.token[%d] %q: scope must be read or admin", i, t.Name)
		}
		if len(t.SHA256) != 64 {
			v.add("web.token[%d] %q: sha256 must be a 64 character hex digest", i, t.Name)
		} else if _, err := hex.DecodeString(t.SHA256); err != nil {
			v.add("web.token[%d] %q: sha256 is not valid hex", i, t.Name)
		}
	}
}

// metrics checks the [metrics] section.
func (v *validator) metrics() {
	if v.c.Metrics.Enabled {
		if host, _, err := net.SplitHostPort(v.c.Metrics.Address); err != nil {
			v.add("metrics.address %q: %v", v.c.Metrics.Address, err)
		} else if !isLoopbackHost(host) {
			// Unlike the dashboard, this endpoint has a credential it can
			// actually use: a monitoring system sets a header. So a public
			// bind is allowed, but only authenticated — and only over TLS,
			// because a bearer token sent in the clear on a LAN is a
			// credential handed to whoever is listening. On loopback the
			// endpoint stays open, per the original Checkmk decision.
			if !v.c.HasReadableToken() {
				v.add("metrics.address %q binds beyond loopback but no [[web.token]] with read scope is configured; "+
					"such a listener could never be polled", v.c.Metrics.Address)
			}
			if v.c.TLS.CertFile == "" || v.c.TLS.KeyFile == "" {
				v.add("metrics.address %q binds beyond loopback but no TLS certificate is configured; "+
					"the bearer token would be sent in the clear", v.c.Metrics.Address)
			}
		}
		if !strings.HasPrefix(v.c.Metrics.Path, "/") {
			v.add("metrics.path %q: must start with /", v.c.Metrics.Path)
		}
	}
}

// history checks the [history] and [expiry] sections.
func (v *validator) history() {
	if v.c.History.RetentionDays <= 0 {
		v.add("history.retention_days must be positive")
	}

	// Bounded rather than merely non-negative: the value becomes a
	// time.Duration in days, and a lead time longer than any certificate's
	// own lifetime means "always warn", which is a typo far more often than
	// it is a choice.
	if v.c.Expiry.WarnDays < 0 || v.c.Expiry.WarnDays > maxExpiryWarnDays {
		v.add("expiry.warn_days must be between 0 and %d (0 disables the warnings)", maxExpiryWarnDays)
	}
}

// bounce checks the [bounce] section.
func (v *validator) bounce() {
	// Only bounce.notify may be overridden per client, so that a printer's
	// failures can be routed to whoever administers the printers without
	// duplicating the digest window, volume cap or notify route per client.
	// Every other bounce.* field left set on a client is silently unused by
	// the notifier, which is exactly the "looks configured but does
	// nothing" trap CLAUDE.md's strict decoding otherwise closes.
	clientNotifies := false
	for _, cl := range v.c.Clients {
		if len(cl.Bounce.Notify) > 0 {
			clientNotifies = true
		}
		if cl.Bounce.Sender != "" || cl.Bounce.NotifyRoute != "" || cl.Bounce.DigestMinutes != 0 || cl.Bounce.MaxPerHour != 0 {
			v.add("client %q: bounce.sender, bounce.notify_route, bounce.digest_minutes and bounce.max_per_hour are global-only; only bounce.notify may be set per client", cl.Name)
		}
		// These reach a From: and To: line through fmt.Fprintf, so a CR or LF
		// in one splits the digest's header block. Operator-controlled rather
		// than remote, but it is still a header built by concatenation from an
		// unvalidated string, which CLAUDE.md bans outright.
		for j, n := range cl.Bounce.Notify {
			if !ValidAddress(n) {
				v.add("client %q: bounce.notify[%d] %q is not a valid email address", cl.Name, j, n)
			}
		}
	}
	for j, n := range v.c.Bounce.Notify {
		if !ValidAddress(n) {
			v.add("bounce.notify[%d] %q is not a valid email address", j, n)
		}
	}
	if len(v.c.Bounce.Notify) > 0 || clientNotifies {
		if v.c.Bounce.Sender == "" {
			v.add("bounce.sender is required when notifications are enabled")
		} else if !ValidAddress(v.c.Bounce.Sender) {
			v.add("bounce.sender %q is not a valid email address", v.c.Bounce.Sender)
		}
		if v.c.Bounce.DigestMinutes <= 0 {
			v.add("bounce.digest_minutes must be positive when notifications are enabled")
		}
		if v.c.Bounce.MaxPerHour <= 0 {
			v.add("bounce.max_per_hour must be positive when notifications are enabled")
		}
		if v.c.Bounce.NotifyRoute == "" {
			v.add("bounce.notify_route is required when notifications are enabled")
		} else if !v.routeNames[v.c.Bounce.NotifyRoute] {
			v.add("bounce.notify_route %q references an unknown route", v.c.Bounce.NotifyRoute)
		}
	}
}

// canaries checks the [[canary]] section.
func (v *validator) canaries() {
	if len(v.c.Canaries) > 0 {
		// The canary's whole purpose is to report a failure through the
		// bounce digest (see internal/canary): without bounce.notify, that
		// failure would have nowhere to go, and the feature would silently
		// do nothing useful on the one path an operator actually cares
		// about. Failing closed here is cheaper than a canary an operator
		// believes is being watched but is not. Checked once, not per
		// canary: it is one shared dependency, not a per-entry one.
		if len(v.c.Bounce.Notify) == 0 {
			v.add("[[canary]] is configured but bounce.notify is empty; canary failures are reported through the bounce digest, so bounce.notify must be configured too")
		}
	}
	canaryNames := map[string]bool{}
	for i, cn := range v.c.Canaries {
		if !ValidName(cn.Name) {
			v.add("canary[%d]: name must be 1 to %d printable ASCII characters without a quote or backslash", i, maxNameLen)
		} else if canaryNames[cn.Name] {
			v.add("canary[%d]: name %q is used by more than one [[canary]]", i, cn.Name)
		} else if v.clientNames[cn.Name] {
			// Client is what the bounce digest groups by, for a canary the
			// same as for a real client's messages (internal/bounce's
			// recipientsFor). A canary sharing a client's name would have
			// its failures silently routed to that client's own bounce
			// override instead of the global list, which is confusing
			// enough to reject outright rather than document as a gotcha.
			v.add("canary[%d]: name %q is also a configured client name; canary names must not collide with client names", i, cn.Name)
		} else {
			canaryNames[cn.Name] = true
		}
		if !ValidAddress(cn.Recipient) {
			v.add("canary[%d] %q: recipient %q is not a valid email address", i, cn.Name, cn.Recipient)
		}
		if cn.Sender == "" {
			v.add("canary[%d] %q: sender is required", i, cn.Name)
		} else if !ValidAddress(cn.Sender) {
			v.add("canary[%d] %q: sender %q is not a valid email address", i, cn.Name, cn.Sender)
		}
		if cn.Route == "" {
			v.add("canary[%d] %q: route is required", i, cn.Name)
		} else if !v.routeNames[cn.Route] {
			v.add("canary[%d] %q: route %q references an unknown route", i, cn.Name, cn.Route)
		}
		// A canary needs exactly one schedule. Both is refused rather than
		// silently preferring one, because the two answer the "is it
		// overdue?" question an alert asks with different numbers, and
		// neither is refused because a canary that never sends is
		// indistinguishable from one that is configured but broken.
		switch {
		case len(cn.DailyAt) > 0 && cn.IntervalMinutes != 0:
			v.add("canary[%d] %q: interval_minutes and daily_at are mutually exclusive; configure exactly one of them", i, cn.Name)
		case len(cn.DailyAt) > 0:
			if _, err := cn.DailyAt.Minutes(); err != nil {
				v.add("canary[%d] %q: daily_at: %v", i, cn.Name, err)
			}
		case cn.IntervalMinutes > 0:
		default:
			v.add("canary[%d] %q: a schedule is required: either interval_minutes (positive) or daily_at (\"HH:MM\" in UTC, or an array of them)", i, cn.Name)
		}
	}
}

// limits checks the [limits] section.
func (v *validator) limits() {
	if v.c.Limits.MaxHops <= 0 || v.c.Limits.MaxConnections <= 0 {
		v.add("limits.max_hops and limits.max_connections must be positive")
	}
	if v.c.Limits.MaxMessageMB <= 0 {
		v.add("limits.max_message_mb must be positive")
	}
	if v.c.Limits.MaxHeaders <= 0 {
		v.add("limits.max_headers must be positive")
	}
	if v.c.Limits.MaxHeaderBytes <= 0 {
		v.add("limits.max_header_bytes must be positive")
	}
	if v.c.Limits.DeliveryTimeoutSec <= 0 {
		v.add("limits.delivery_timeout_sec must be positive")
	} else if want := v.c.Limits.MaxMessageMB; want > 0 {
		// A budget that cannot carry the largest message the relay will
		// accept turns every such message into a retry loop that only ends
		// when queue.max_lifetime_hours expires it. 1 MB/s is a deliberately
		// pessimistic floor; the point is to catch a budget that is orders of
		// magnitude too small, not to model the link.
		if need := want + 30; v.c.Limits.DeliveryTimeoutSec < need {
			v.add("limits.delivery_timeout_sec %d is too small for limits.max_message_mb %d: "+
				"a message that size needs at least %d seconds at 1 MB/s plus handshake, "+
				"and a shorter budget makes large mail retry until it expires",
				v.c.Limits.DeliveryTimeoutSec, want, need)
		}
	}
	// Spool.SetQuota reads anything at or below zero as "no quota", and a
	// value large enough to overflow int64 gigabytes-to-bytes used to mean the
	// same. Both are rejected here so the only way to have no quota is to say
	// so.
	switch {
	case v.c.Limits.SpoolMaxGB < 0:
		v.add("limits.spool_max_gb must not be negative (0 means no quota)")
	case v.c.Limits.SpoolMaxGB > maxSpoolGB:
		v.add("limits.spool_max_gb %d is beyond any real filesystem; the maximum is %d",
			v.c.Limits.SpoolMaxGB, maxSpoolGB)
	}
	if v.c.Limits.SpoolWarnPercent < 0 || v.c.Limits.SpoolWarnPercent > 100 {
		v.add("limits.spool_warn_percent must be between 0 and 100")
	}
	for _, cl := range v.c.Clients {
		if cl.MaxMessageMB > v.c.Limits.MaxMessageMB {
			v.add("client %q: max_message_mb %d exceeds limits.max_message_mb %d",
				cl.Name, cl.MaxMessageMB, v.c.Limits.MaxMessageMB)
		}
	}
}

// Route returns the route a client delivers through, falling back to the
// route marked default.
func (c *Config) Route(name string) (Route, bool) {
	for _, r := range c.Routes {
		if r.Name == name {
			return r, true
		}
	}
	if name == "" {
		for _, r := range c.Routes {
			if r.Default {
				return r, true
			}
		}
	}
	return Route{}, false
}

// ParseTLSVersion maps a configured version string onto a crypto/tls constant.
func ParseTLSVersion(s string) (uint16, error) {
	switch s {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version %q", s)
	}
}

// maxNameLen bounds a configured name. Long enough for any descriptive name,
// short enough that one cannot bloat a log line or a metrics exposition.
const maxNameLen = 64

// ValidName reports whether s is usable as a listener, client, route, canary
// or token name.
//
// These names are not confined to the configuration file: they become
// Prometheus label values, structured log fields, history journal columns and
// dashboard text. The rule is deliberately permissive -- any printable ASCII,
// spaces included -- and excludes exactly the three things that break a
// downstream format: control characters (which would split a log line or a
// Received header), the double quote and the backslash (which are what a
// Prometheus label value has to escape).
//
// metrics.label escapes those anyway and should keep doing so, but until this
// existed its comment claimed the loader guaranteed a safe character set when
// the loader checked only for empty and duplicate names.
func ValidName(s string) bool {
	if s == "" || len(s) > maxNameLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// printableASCII reports whether s consists only of characters that survive a
// SASL payload unchanged.
func printableASCII(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// IsLoopbackHost reports whether host names the local machine only. Exported
// because the metrics listener has to make the same distinction at serve time
// that this package makes at validation time, and two spellings of "is this
// loopback" is one more than the number that can be right.
func IsLoopbackHost(host string) bool { return isLoopbackHost(host) }

// IsLoopbackHostHeader reports whether an HTTP Host header names the local
// machine. It exists because "the listener is bound to loopback" and "this
// request was addressed to loopback" are different statements: a browser
// resolves a name the page controls, so a DNS rebind reaches a loopback
// listener with an attacker's name in the Host header, from inside the
// boundary the loopback bind was supposed to be.
//
// The header may carry a port or not, and an IPv6 literal arrives in
// brackets, so both shapes are reduced to a bare host before the same
// loopback test the validator uses.
func IsLoopbackHostHeader(hostHeader string) bool {
	h := hostHeader
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	} else {
		h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	}
	return isLoopbackHost(h)
}

func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}
