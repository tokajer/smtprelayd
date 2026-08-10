// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

import (
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
const secretExpiresLayout = "2006-01-02"

// tenantID bounds what may be interpolated into the token endpoint URL. A
// tenant is a GUID or a domain name; anything that could add or traverse a
// path segment is rejected before it reaches net/url.
var tenantID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`)

// ValidTenantID reports whether s is safe to place in the token endpoint path.
func ValidTenantID(s string) bool { return tenantID.MatchString(s) }

// Validate enforces every rule from docs/SECURITY.md that can be decided
// without touching the network. Ambiguity is an error, never a warning.
func (c *Config) Validate() error {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	if c.Service.DataDir == "" {
		add("service.data_dir is required")
	}
	if _, err := ParseLevel(c.Service.LogLevel); err != nil {
		add("service.log_level: %v", err)
	}
	if c.Service.Hostname == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			add("service.hostname is required (host name could not be determined)")
		} else {
			c.Service.Hostname = h
		}
	}

	if len(c.Listeners) == 0 {
		add("at least one [[listener]] is required")
	}
	needsCert := false
	anyPublic := false
	names := map[string]bool{}
	for i, l := range c.Listeners {
		where := fmt.Sprintf("listener[%d] %q", i, l.Name)
		if l.Name == "" {
			add("%s: name is required", where)
		} else if names[l.Name] {
			add("%s: duplicate listener name", where)
		}
		names[l.Name] = true

		host, _, err := net.SplitHostPort(l.Address)
		if err != nil {
			add("%s: address %q: %v", where, l.Address, err)
		} else if !isLoopbackHost(host) {
			anyPublic = true
		}
		switch l.TLS {
		case "none", "starttls", "implicit":
		case "":
			c.Listeners[i].TLS = "none"
		default:
			add("%s: tls must be none, starttls or implicit", where)
		}
		if c.Listeners[i].TLS != "none" {
			needsCert = true
		}
		if l.RequireTLS && c.Listeners[i].TLS == "none" {
			add("%s: require_tls is set but tls is none", where)
		}
		if l.MinTLS != "" {
			if _, err := ParseTLSVersion(l.MinTLS); err != nil {
				add("%s: min_tls: %v", where, err)
			}
		}
	}
	if needsCert {
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			add("[tls] cert_file and key_file are required when a listener uses TLS")
		} else if _, err := tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile); err != nil {
			add("[tls]: %v", err)
		}
	}

	// Fail closed. An empty allowlist is a configuration error and never an
	// implicit "allow all" -- an open relay is the one failure that cannot be
	// recovered from cheaply.
	if len(c.Clients) == 0 {
		if anyPublic {
			add("no [[client]] is defined but a listener binds a non-loopback address: this would be an open relay")
		} else {
			add("at least one [[client]] is required")
		}
	}

	type owned struct {
		prefix netip.Prefix
		owner  string
	}
	var prefixes []owned
	clientNames := map[string]bool{}
	for i := range c.Clients {
		cl := &c.Clients[i]
		where := fmt.Sprintf("client[%d] %q", i, cl.Name)
		if cl.Name == "" {
			add("%s: name is required", where)
		} else if clientNames[cl.Name] {
			add("%s: duplicate client name", where)
		}
		clientNames[cl.Name] = true

		if len(cl.CIDR) == 0 {
			add("%s: at least one cidr is required", where)
		}
		for _, s := range cl.CIDR {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				add("%s: cidr %q: %v", where, s, err)
				continue
			}
			if p.Addr() != p.Masked().Addr() {
				add("%s: cidr %q has host bits set, use %s", where, s, p.Masked())
				continue
			}
			for _, o := range prefixes {
				if o.prefix.Overlaps(p) {
					add("%s: cidr %s overlaps %s of client %q: matching would be ambiguous",
						where, p, o.prefix, o.owner)
				}
			}
			prefixes = append(prefixes, owned{prefix: p, owner: cl.Name})
		}

		switch cl.Rewrite.Mode {
		case "", "off":
			c.Clients[i].Rewrite.Mode = "off"
		case "force", "if_unauthorized":
			switch {
			case cl.Rewrite.EnvelopeFrom == "":
				add("%s: rewrite.envelope_from is required for mode %s", where, cl.Rewrite.Mode)
			case !ValidAddress(cl.Rewrite.EnvelopeFrom):
				add("%s: rewrite.envelope_from %q is not a valid address", where, cl.Rewrite.EnvelopeFrom)
			}
			// An empty allowlist would make if_unauthorized behave exactly
			// like force while reading as if it were selective.
			if cl.Rewrite.Mode == "if_unauthorized" && len(cl.Rewrite.AllowedSenders) == 0 {
				add("%s: rewrite.mode if_unauthorized requires at least one allowed_senders entry", where)
			}
			if hf := strings.TrimSpace(cl.Rewrite.HeaderFrom); hf != "" && hf != "keep" {
				_, addr, ok := SplitMailbox(hf)
				switch {
				case !ok:
					add("%s: rewrite.header_from must be keep, an address, or "+
						"a printable ASCII display name followed by <address>", where)
				case DomainOf(addr) != DomainOf(cl.Rewrite.EnvelopeFrom):
					// SPF checks the envelope and DMARC checks the header, so
					// a split between the two domains fails alignment at the
					// smarthost and is never what the operator wanted.
					add("%s: rewrite.header_from domain %q does not match rewrite.envelope_from domain %q",
						where, DomainOf(addr), DomainOf(cl.Rewrite.EnvelopeFrom))
				}
			}
		default:
			add("%s: rewrite.mode must be off, if_unauthorized or force", where)
		}
		for j, p := range cl.Rewrite.AllowedSenders {
			if !ValidSenderPattern(p) {
				add("%s: rewrite.allowed_senders[%d] %q must be an address or *@domain", where, j, p)
			}
		}
		switch rt := strings.TrimSpace(cl.Rewrite.ReplyTo); {
		case rt == "" || rt == "preserve" || rt == "drop":
		case strings.HasPrefix(rt, "fixed:"):
			if !ValidAddress(strings.TrimSpace(strings.TrimPrefix(rt, "fixed:"))) {
				add("%s: rewrite.reply_to fixed address is not valid", where)
			}
		default:
			add("%s: rewrite.reply_to must be preserve, drop or fixed:<address>", where)
		}
		if cl.MaxMessageMB < 0 || cl.MaxRecipients < 0 {
			add("%s: limits must not be negative", where)
		}
	}

	routeNames := map[string]bool{}
	domainOwner := map[string]string{}
	var sourcePrefixes []owned
	defaults := 0
	for i := range c.Routes {
		r := &c.Routes[i]
		where := fmt.Sprintf("route[%d] %q", i, r.Name)
		if r.Name == "" {
			add("%s: name is required", where)
		} else if routeNames[r.Name] {
			add("%s: duplicate route name", where)
		}
		routeNames[r.Name] = true
		if r.Default {
			defaults++
		}
		if r.Host == "" {
			add("%s: host is required", where)
		}
		if r.Port == 0 {
			c.Routes[i].Port = 587
		} else if r.Port < 1 || r.Port > 65535 {
			add("%s: port %d is out of range", where, r.Port)
		}
		switch r.TLS {
		case "starttls", "implicit":
		case "none":
			// Cleartext delivery exists for smarthosts on a segment the
			// operator controls end to end. It is never a fallback: a route
			// asking for TLS that cannot negotiate it defers, it does not
			// downgrade. Settings that only describe a handshake are an
			// error here rather than silently ignored, because a route
			// carrying min_tls reads as if it were still encrypted.
			if r.MinTLS != "" {
				add("%s: min_tls is meaningless with tls none, remove it", where)
			}
			if r.CAPin != "" {
				add("%s: ca_pin is meaningless with tls none, remove it", where)
			}
		case "":
			c.Routes[i].TLS = "starttls"
		default:
			add("%s: tls must be none, starttls or implicit", where)
		}
		if c.Routes[i].TLS == "none" {
			// Credentials are never put on an unprotected wire. A bearer
			// token read off it grants mailbox access far beyond this relay,
			// and PLAIN hands over the password outright; net/smtp refuses
			// PlainAuth on an unencrypted connection anyway, so accepting it
			// here would only turn a startup error into a delivery failure.
			if r.Auth != "" && r.Auth != "none" {
				add("%s: auth %s requires tls starttls or implicit; "+
					"tls none supports auth none only", where, r.Auth)
			}
		} else if r.MinTLS == "" {
			c.Routes[i].MinTLS = "1.2"
		} else if v, err := ParseTLSVersion(r.MinTLS); err != nil {
			add("%s: min_tls: %v", where, err)
		} else if v < tls.VersionTLS12 {
			add("%s: min_tls must be at least 1.2 for outbound connections", where)
		}
		switch r.Auth {
		case "none":
		case "plain", "login":
			if r.Credentials.Username == "" || r.Credentials.Password.Empty() {
				add("%s: auth %s requires credentials.username and credentials.password", where, r.Auth)
			}
		case "xoauth2":
			o := r.OAuth2
			switch {
			case o.TenantID == "" || o.ClientID == "" || o.ClientSecret.Empty() || o.Mailbox == "":
				add("%s: auth xoauth2 requires oauth2 tenant_id, client_id, client_secret and mailbox", where)
			default:
				if !ValidTenantID(o.TenantID) {
					add("%s: oauth2.tenant_id must be a tenant GUID or domain name", where)
				}
				// The mailbox is concatenated into the XOAUTH2 payload around
				// \x01 separators, so anything outside printable ASCII could
				// forge a field.
				if !printableASCII(o.Mailbox) || !strings.Contains(o.Mailbox, "@") {
					add("%s: oauth2.mailbox must be an ASCII email address", where)
				}
				if o.Scope == "" {
					c.Routes[i].OAuth2.Scope = DefaultScope
				} else if !strings.HasPrefix(o.Scope, "https://") || !strings.HasSuffix(o.Scope, "/.default") {
					add("%s: oauth2.scope must be an https resource scope ending in /.default", where)
				}
				if o.SecretExpires != "" {
					if _, err := time.Parse(secretExpiresLayout, o.SecretExpires); err != nil {
						add("%s: oauth2.secret_expires must be YYYY-MM-DD", where)
					}
				}
			}
		case "":
			add("%s: auth is required (none, plain, login or xoauth2)", where)
		default:
			add("%s: auth must be none, plain, login or xoauth2", where)
		}
		if r.CAPin != "" {
			if _, err := hex.DecodeString(strings.ReplaceAll(r.CAPin, ":", "")); err != nil {
				add("%s: ca_pin must be a hex SHA-256 fingerprint", where)
			}
		}
		if r.MaxConcurrent <= 0 {
			c.Routes[i].MaxConcurrent = 4
		}

		// Recipient domains take precedence over the route named by the
		// client, so a domain claimed twice would silently pick one of them.
		for j, d := range r.Domains {
			dl := strings.ToLower(strings.TrimSpace(d))
			if !ValidDomain(dl) {
				add("%s: domains[%d] %q is not a valid domain name", where, j, d)
				continue
			}
			if owner, dup := domainOwner[dl]; dup {
				add("%s: domain %q is already routed by route %q", where, dl, owner)
				continue
			}
			domainOwner[dl] = r.Name
			c.Routes[i].Domains[j] = dl
		}

		// Source networks may deliberately overlap a client CIDR -- that is
		// how a site-wide route coexists with a per-device one -- but two
		// routes claiming the same network would be ambiguous.
		for j, src := range r.Sources {
			p, err := netip.ParsePrefix(src)
			if err != nil {
				add("%s: sources[%d] %q: %v", where, j, src, err)
				continue
			}
			if p.Addr() != p.Masked().Addr() {
				add("%s: sources[%d] %q has host bits set, use %s", where, j, src, p.Masked())
				continue
			}
			for _, o := range sourcePrefixes {
				if o.prefix.Overlaps(p) {
					add("%s: sources %s overlaps %s of route %q: matching would be ambiguous",
						where, p, o.prefix, o.owner)
				}
			}
			sourcePrefixes = append(sourcePrefixes, owned{prefix: p, owner: r.Name})
		}
	}
	if len(c.Routes) == 0 {
		add("at least one [[route]] is required")
	}
	if defaults > 1 {
		add("more than one route is marked default")
	}
	for _, cl := range c.Clients {
		if cl.Route == "" {
			if defaults == 0 {
				add("client %q has no route and no default route exists", cl.Name)
			}
			continue
		}
		if !routeNames[cl.Route] {
			add("client %q references unknown route %q", cl.Name, cl.Route)
		}
	}

	if len(c.Queue.RetryScheduleMin) == 0 {
		add("queue.retry_schedule_min must not be empty")
	}
	for _, m := range c.Queue.RetryScheduleMin {
		if m <= 0 {
			add("queue.retry_schedule_min must contain positive values")
		}
	}
	if c.Queue.MaxLifetimeHours <= 0 {
		add("queue.max_lifetime_hours must be positive")
	}

	if c.Web.Enabled {
		if host, _, err := net.SplitHostPort(c.Web.Address); err != nil {
			add("web.address %q: %v", c.Web.Address, err)
		} else if !isLoopbackHost(host) && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
			add("web.address binds beyond loopback but no TLS certificate is configured")
		}
	}
	for i, t := range c.Web.Tokens {
		if t.Scope != "read" && t.Scope != "admin" {
			add("web.token[%d] %q: scope must be read or admin", i, t.Name)
		}
		if len(t.SHA256) != 64 {
			add("web.token[%d] %q: sha256 must be a 64 character hex digest", i, t.Name)
		} else if _, err := hex.DecodeString(t.SHA256); err != nil {
			add("web.token[%d] %q: sha256 is not valid hex", i, t.Name)
		}
	}
	if c.Metrics.Enabled {
		if _, _, err := net.SplitHostPort(c.Metrics.Address); err != nil {
			add("metrics.address %q: %v", c.Metrics.Address, err)
		}
	}

	if c.Limits.MaxHops <= 0 || c.Limits.MaxConnections <= 0 {
		add("limits.max_hops and limits.max_connections must be positive")
	}
	if c.Limits.MaxMessageMB <= 0 {
		add("limits.max_message_mb must be positive")
	}
	for _, cl := range c.Clients {
		if cl.MaxMessageMB > c.Limits.MaxMessageMB {
			add("client %q: max_message_mb %d exceeds limits.max_message_mb %d",
				cl.Name, cl.MaxMessageMB, c.Limits.MaxMessageMB)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config %s:\n  - %s", c.Path, strings.Join(errs, "\n  - "))
	}
	return nil
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
