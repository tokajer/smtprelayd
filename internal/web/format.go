// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
)

// Presentation helpers for the dashboard templates: link building, paging
// parameters and the value formatting the configuration page renders. None of
// them touch the store, the spool or the request, which is why they live
// apart from the handlers.

// parseNonNegative reads a whole number from a query parameter, answering
// zero for anything unparsable or negative rather than failing. Both callers
// want that: a pagination offset is a position in a list, and the bulk banner
// below is rebuilt from counts this process itself put in the redirect, so
// neither is worth refusing a request over.
func parseNonNegative(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// parseOffset reads a pagination offset. It is parseNonNegative under the
// name the paging code reads by; the bulk flash counts use the primitive
// directly, because calling something "offset" while parsing "how many
// messages were deleted" made that code read as if it were paging.
func parseOffset(s string) int { return parseNonNegative(s) }

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
// read-only configuration view as plain text. All four are thin callers over
// formatBlock, which walks a toml-tagged config struct by reflection: hand
// writing four field lists was how the page came to omit fields nobody
// noticed were missing -- min_tls, ca_pin and most of a client's rewrite
// block among them -- since adding a field to config.go was never required
// to add a line here too.
//
// None of them ever calls Secret.Value(): formatBlock recognises
// config.Secret by name and renders it through String(), which returns
// "[redacted]", never descending into it -- so there are two independent
// reasons a secret can never leak onto this page, not one.
func formatListeners(ls []config.Listener) string {
	if len(ls) == 0 {
		return "(none configured)"
	}
	blocks := make([]string, len(ls))
	for i, l := range ls {
		blocks[i] = formatBlock(fmt.Sprintf("[listener %q]", l.Name), reflect.ValueOf(l), nil)
	}
	return strings.Join(blocks, "\n\n")
}

func formatClients(cs []config.Client) string {
	if len(cs) == 0 {
		return "(none configured)"
	}
	blocks := make([]string, len(cs))
	for i, c := range cs {
		blocks[i] = formatBlock(fmt.Sprintf("[client %q]", c.Name), reflect.ValueOf(c), nil)
	}
	return strings.Join(blocks, "\n\n")
}

func formatRoutes(rs []config.Route) string {
	if len(rs) == 0 {
		return "(none configured)"
	}
	blocks := make([]string, len(rs))
	for i, r := range rs {
		// The oauth2.* lines only mean anything for an xoauth2 route and the
		// credentials.* lines only for plain/login, so the other block is
		// skipped rather than shown empty or, worse, shown with the fields
		// an operator would read as configured for an auth mode that
		// ignores them.
		skip := func(key string) bool {
			switch {
			case strings.HasPrefix(key, "oauth2."):
				return r.Auth != config.AuthXOAUTH2
			case strings.HasPrefix(key, "credentials."):
				return r.Auth != config.AuthPlain && r.Auth != config.AuthLogin
			}
			return false
		}
		blocks[i] = formatBlock(fmt.Sprintf("[route %q]", r.Name), reflect.ValueOf(r), skip)
	}
	return strings.Join(blocks, "\n\n")
}

func formatBounce(b config.Bounce) string {
	return formatBlock("", reflect.ValueOf(b), nil)
}

// kv is one rendered "key = value" line, in the order formatBlock's fields
// were declared.
type kv struct{ key, value string }

// formatBlock renders one config value as the configuration page's plain
// text block: header (or none, for [bounce], which the caller passes as
// ""), then one key = value line per toml-tagged field, keys padded to the
// widest one in the block. skip, if non-nil, is asked about each field's
// dotted key before it is rendered or descended into.
func formatBlock(header string, v reflect.Value, skip func(key string) bool) string {
	var fields []kv
	flattenFields(v, "", skip, &fields)

	width := 0
	for _, f := range fields {
		width = max(width, len(f.key))
	}

	var b strings.Builder
	if header != "" {
		b.WriteString(header)
		b.WriteString("\n")
	}
	for _, f := range fields {
		fmt.Fprintf(&b, "%-*s = %s\n", width, f.key, f.value)
	}
	return strings.TrimRight(b.String(), "\n")
}

// flattenFields walks a toml-tagged config struct and appends one kv per
// leaf field, in declaration order, dotting a nested struct's tag onto its
// own (rewrite.mode, oauth2.tenant_id). config.Secret is matched by concrete
// type rather than an fmt.Stringer assertion, so this can never be fooled
// into rendering some other type's String() unredacted. The struct's own
// "name" field, if it has one, is the caller's section header and is not
// repeated as a body line.
func flattenFields(v reflect.Value, prefix string, skip func(key string) bool, out *[]kv) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("toml")
		if tag == "" || tag == "-" {
			continue
		}
		if prefix == "" && tag == "name" {
			continue
		}
		key := tag
		if prefix != "" {
			key = prefix + "." + tag
		}
		if skip != nil && skip(key) {
			continue
		}

		fv := v.Field(i)
		if sec, ok := fv.Interface().(config.Secret); ok {
			val := sec.String()
			if sec.Empty() {
				val = "(none)"
			}
			*out = append(*out, kv{key, val})
			continue
		}

		switch fv.Kind() {
		case reflect.Struct:
			flattenFields(fv, key, skip, out)
		case reflect.Slice:
			if fv.Type().Elem().Kind() == reflect.Struct {
				// fmt.Sprint on a struct element reaches its unexported
				// fields too, which for a slice of sub-blocks containing a
				// config.Secret would print it unredacted.
				*out = append(*out, kv{key, fmt.Sprintf("(%d entries)", fv.Len())})
				continue
			}
			items := make([]string, fv.Len())
			for j := range items {
				items[j] = fmt.Sprint(fv.Index(j).Interface())
			}
			*out = append(*out, kv{key, orNone(strings.Join(items, ", "))})
		case reflect.String:
			*out = append(*out, kv{key, orNone(fv.String())})
		default:
			*out = append(*out, kv{key, fmt.Sprintf("%v", fv.Interface())})
		}
	}
}
