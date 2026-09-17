// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
)

// Presentation helpers for the dashboard templates: link building, paging
// parameters and the value formatting the configuration page renders. None of
// them touch the store, the spool or the request, which is why they live
// apart from the handlers.

// parseOffset reads a pagination offset from a query parameter. Anything
// unparsable or negative is the first page rather than an error: an offset is
// a position in a list, and refusing the request over one would be a worse
// answer than showing the start.
func parseOffset(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// filterQueryValues copies the named parameters out of q, dropping paging
// and sort parameters, so a pagination link can carry the active filters
// forward without also carrying along a stale offset.
func filterQueryValues(q url.Values, keys ...string) url.Values {
	out := url.Values{}
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			out.Set(k, v)
		}
	}
	return out
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}

// sortLinks builds the header link for each sortable queue column. Clicking
// the active column toggles its order; clicking any other column sorts by
// it descending first, which for a log-like table surfaces the newest or
// highest-cardinality rows first.
func sortLinks(path string, extra url.Values, currentSort, currentOrder string) map[string]string {
	effSort := currentSort
	if effSort == "" {
		effSort = "received_at"
	}
	effOrder := currentOrder
	if effOrder != "asc" {
		effOrder = "desc"
	}
	cols := []string{"received_at", "status", "client", "route"}
	out := make(map[string]string, len(cols))
	for _, col := range cols {
		order := "desc"
		if col == effSort && effOrder == "desc" {
			order = "asc"
		}
		v := cloneValues(extra)
		v.Set("sort", col)
		v.Set("order", order)
		out[col] = path + "?" + v.Encode()
	}
	return out
}

func pageHref(path string, extra url.Values, sortCol, order string, offset int) string {
	v := cloneValues(extra)
	if sortCol != "" {
		v.Set("sort", sortCol)
	}
	if order != "" {
		v.Set("order", order)
	}
	if offset > 0 {
		v.Set("offset", strconv.Itoa(offset))
	}
	if enc := v.Encode(); enc != "" {
		return path + "?" + enc
	}
	return path
}

// formatBytes renders a spooled size for a table cell. Below a kilobyte the
// exact octet count is kept, since that range is where a truncated or empty
// message is being diagnosed and rounding would hide it.
func formatBytes(n int64) string {
	switch {
	case n < 1024:
		return strconv.FormatInt(n, 10) + " B"
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	}
}

// localtimeFunc builds the "localtime" template func. It accepts both
// time.Time (e.g. Message.ReceivedAt) and *time.Time (e.g. Attempt.NextAt,
// which templates already guard with {{if .NextAt}} before calling this) so
// every timestamp field in the dashboard can go through the same helper.
func localtimeFunc(loc *time.Location) func(any, string) string {
	return func(v any, layout string) string {
		var t time.Time
		switch x := v.(type) {
		case time.Time:
			t = x
		case *time.Time:
			if x == nil {
				return ""
			}
			t = *x
		default:
			return ""
		}
		if loc != nil {
			t = t.In(loc)
		}
		return t.Format(layout)
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// formatListeners, formatClients, formatRoutes and formatBounce render the
// read-only configuration view as plain text. None of them ever calls
// Secret.Value(): a client secret or SMTP password is written as the fixed
// string "[redacted]" regardless of what Secret.String() would already
// return, so there are two independent reasons this can never leak, not one.
func formatListeners(ls []config.Listener) string {
	if len(ls) == 0 {
		return "(none configured)"
	}
	var b strings.Builder
	for _, l := range ls {
		fmt.Fprintf(&b, "[listener %q]\naddress     = %s\ntls         = %s\nmin_tls     = %s\nrequire_tls = %v\n\n",
			l.Name, l.Address, orNone(l.TLS), orNone(l.MinTLS), l.RequireTLS)
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatClients(cs []config.Client) string {
	if len(cs) == 0 {
		return "(none configured)"
	}
	var b strings.Builder
	for _, c := range cs {
		fmt.Fprintf(&b, "[client %q]\ncidr               = %s\nroute              = %s\nmax_message_mb     = %d\nmax_recipients     = %d\nrate_limit_per_min = %d\nmax_connections    = %d\nrewrite.mode       = %s\n\n",
			c.Name, strings.Join(c.CIDR, ", "), c.Route, c.MaxMessageMB, c.MaxRecipients,
			c.RateLimitPerMin, c.MaxConnections, orNone(c.Rewrite.Mode))
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatRoutes(rs []config.Route) string {
	if len(rs) == 0 {
		return "(none configured)"
	}
	var b strings.Builder
	for _, r := range rs {
		fmt.Fprintf(&b, "[route %q]\ndefault            = %v\nhost               = %s\nport               = %d\ntls                = %s\nauth               = %s\ndomains            = %s\nsources            = %s\nmax_concurrent     = %d\nrate_limit_per_min = %d\n",
			r.Name, r.Default, r.Host, r.Port, orNone(r.TLS), orNone(r.Auth),
			strings.Join(r.Domains, ", "), strings.Join(r.Sources, ", "), r.MaxConcurrent, r.RateLimitPerMin)
		switch r.Auth {
		case "xoauth2":
			fmt.Fprintf(&b, "oauth2.tenant_id     = %s\noauth2.client_id     = %s\noauth2.mailbox       = %s\noauth2.client_secret = [redacted]\n",
				r.OAuth2.TenantID, r.OAuth2.ClientID, r.OAuth2.Mailbox)
		case "plain", "login":
			fmt.Fprintf(&b, "credentials.username = %s\ncredentials.password = [redacted]\n", r.Credentials.Username)
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatBounce(b config.Bounce) string {
	return fmt.Sprintf("sender         = %s\nnotify         = %s\nnotify_route   = %s\ndigest_minutes = %d\nmax_per_hour   = %d",
		orNone(b.Sender), strings.Join(b.Notify, ", "), orNone(b.NotifyRoute), b.DigestMinutes, b.MaxPerHour)
}
