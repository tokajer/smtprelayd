// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

//go:embed static/style.css
var styleCSS []byte

//go:embed templates/*.html
var templateFS embed.FS

// pageSize bounds how many rows a single dashboard page shows. It matches
// the plan's default page size for the eventual JSON API in phase 4d, so
// the two do not disagree about what "a page" means.
const pageSize = 50

// Server renders the read-only observability dashboard: live queue,
// search, bounces, per-message detail, route status and a read-only
// configuration view. It never reads a message body and never exposes a
// secret, regardless of which config field is asked for.
type Server struct {
	cfg     *config.Config
	store   *store.Store
	spool   *spool.Spool
	metrics *metrics.Registry
	version string
	log     *slog.Logger
	tmpl    map[string]*template.Template
	csrf    *csrfSigner
	css     []byte
	theme   string
}

// New parses the embedded templates and builds a dashboard server. cfg, st,
// sp and reg must outlive the server; nothing here mutates them, and reg may
// be nil if metrics are disabled, in which case the route sidebar is empty.
func New(cfg *config.Config, st *store.Store, sp *spool.Spool, reg *metrics.Registry, version string, log *slog.Logger) (*Server, error) {
	pages := []string{"queue", "search", "bounces", "message", "routes", "config"}
	tmpl := make(map[string]*template.Template, len(pages))
	funcs := template.FuncMap{"bytes": formatBytes}
	for _, name := range pages {
		t, err := template.New(name).Funcs(funcs).ParseFS(templateFS,
			"templates/layout.html", "templates/sidebar.html", "templates/pager.html",
			"templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("web: parse template %s: %w", name, err)
		}
		tmpl[name] = t
	}
	csrf, err := newCSRFSigner()
	if err != nil {
		return nil, fmt.Errorf("web: generating CSRF key: %w", err)
	}
	// The themed stylesheet is assembled once here rather than per request:
	// the configuration cannot change while the process runs, so a request
	// that regenerated it could only ever produce the same bytes.
	css := append(append([]byte(nil), styleCSS...), themeOverrides(cfg.Web.Theme)...)
	return &Server{
		cfg: cfg, store: st, spool: sp, metrics: reg, version: version,
		log: log.With("component", "web"), tmpl: tmpl, csrf: csrf,
		css: css, theme: themeMode(cfg.Web.Theme),
	}, nil
}

// baseData is embedded in every page's template data so the shared header
// and sidebar have what they need regardless of which page is rendering.
type baseData struct {
	Version       string
	Page          string
	Theme         string
	Routes        []metrics.RouteStatus
	Totals        totals
	RecentBounces []*store.Message
}

// totals is the sum of the per-route counters already held in memory for the
// header tiles. It deliberately adds no query of its own: the tiles are the
// same numbers /metrics and the route page report, summed.
type totals struct {
	Queued, Deferred int
	Delivered        uint64
	Bounced          uint64
}

func (s *Server) base(page string) baseData {
	var routes []metrics.RouteStatus
	if s.metrics != nil {
		routes = s.metrics.Status()
	}
	var sum totals
	for _, r := range routes {
		sum.Queued += r.Queued
		sum.Deferred += r.Deferred
		sum.Delivered += r.Delivered
		sum.Bounced += r.Bounced
	}
	recent, err := s.store.FindBounces(store.BounceFilter{Limit: 5})
	if err != nil {
		s.log.Warn("sidebar: recent bounces query failed", "error", err)
		recent = nil
	}
	if len(recent) > 5 {
		recent = recent[:5]
	}
	s.redactSubjects(recent)
	return baseData{
		Version: s.version, Page: page, Theme: s.theme,
		Routes: routes, Totals: sum, RecentBounces: recent,
	}
}

// redactSubjects overwrites Subject with a fixed marker when the operator
// has disabled subject retention. store.RecordMessage already writes an
// empty string in that case for every row, so this cannot under- or
// over-redact relative to what is actually in the database: it is display
// policy for what the store already enforced at write time, not a second
// independent check.
func (s *Server) redactSubjects(msgs []*store.Message) {
	if s.cfg.History.RetainSubjects {
		return
	}
	for _, m := range msgs {
		m.Subject = "[redacted]"
	}
}

func (s *Server) redactSubject(m *store.Message) {
	if m == nil || s.cfg.History.RetainSubjects {
		return
	}
	m.Subject = "[redacted]"
}

// render executes a named page into a buffer first, so a template error
// produces a clean 500 instead of a truncated 200 page with headers already
// sent.
func (s *Server) render(w http.ResponseWriter, page string, data any) {
	t, ok := s.tmpl[page]
	if !ok {
		http.Error(w, "internal error: unknown page", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		s.log.Error("template execution failed", "page", page, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func (s *Server) serverError(w http.ResponseWriter, page string, err error) {
	s.log.Error("dashboard query failed", "page", page, "error", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func (s *Server) handleStyle(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(s.css)
}

// handleQueue shows messages still in the spool: queued or deferred,
// sortable by the columns the plan calls for.
func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sortCol := q.Get("sort")
	order := q.Get("order")
	offset := parseOffset(q.Get("offset"))

	msgs, err := s.store.FindMessages(store.MessageFilter{
		Status: "active", Sort: sortCol, Order: order, Limit: pageSize, Offset: offset,
	})
	if err != nil {
		s.serverError(w, "queue", err)
		return
	}
	s.redactSubjects(msgs)
	hasMore := len(msgs) > pageSize
	if hasMore {
		msgs = msgs[:pageSize]
	}

	data := struct {
		baseData
		Messages  []*store.Message
		SortLinks map[string]string
		HasMore   bool
		NextHref  string
		PrevHref  string
	}{
		baseData:  s.base("queue"),
		Messages:  msgs,
		SortLinks: sortLinks("/queue", nil, sortCol, order),
		HasMore:   hasMore,
	}
	if hasMore {
		data.NextHref = pageHref("/queue", nil, sortCol, order, offset+pageSize)
	}
	if offset > 0 {
		data.PrevHref = pageHref("/queue", nil, sortCol, order, maxInt(0, offset-pageSize))
	}
	s.render(w, "queue", data)
}

type searchFilterView struct {
	Sender, Recipient, Subject, Client, Route, Status, Since, Until string
}

// handleSearch answers ad hoc queries across the full history, independent
// of whether a message has already left the spool.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	offset := parseOffset(q.Get("offset"))
	filter := store.MessageFilter{
		Sender:    strings.TrimSpace(q.Get("sender")),
		Recipient: strings.TrimSpace(q.Get("recipient")),
		Subject:   strings.TrimSpace(q.Get("subject")),
		Client:    strings.TrimSpace(q.Get("client")),
		Route:     strings.TrimSpace(q.Get("route")),
		Status:    q.Get("status"),
		Limit:     pageSize,
		Offset:    offset,
	}
	filterErr := parseTimeRange(q, &filter.Since, &filter.Until)

	var msgs []*store.Message
	if filterErr == "" {
		var err error
		msgs, err = s.store.FindMessages(filter)
		if err != nil {
			s.serverError(w, "search", err)
			return
		}
	}
	s.redactSubjects(msgs)
	hasMore := len(msgs) > pageSize
	if hasMore {
		msgs = msgs[:pageSize]
	}

	extra := filterQueryValues(q, "sender", "recipient", "subject", "client", "route", "status", "since", "until")
	data := struct {
		baseData
		Filter      searchFilterView
		FilterError string
		Messages    []*store.Message
		HasMore     bool
		NextHref    string
		PrevHref    string
	}{
		baseData: s.base("search"),
		Filter: searchFilterView{
			Sender: filter.Sender, Recipient: filter.Recipient, Subject: filter.Subject,
			Client: filter.Client, Route: filter.Route, Status: filter.Status,
			Since: q.Get("since"), Until: q.Get("until"),
		},
		FilterError: filterErr,
		Messages:    msgs,
		HasMore:     hasMore,
	}
	if hasMore {
		data.NextHref = pageHref("/search", extra, "", "", offset+pageSize)
	}
	if offset > 0 {
		data.PrevHref = pageHref("/search", extra, "", "", maxInt(0, offset-pageSize))
	}
	s.render(w, "search", data)
}

type bounceFilterView struct {
	Sender, Recipient, Subject, Client, Route, Class, Since, Until string
}

// handleBounces mirrors search with the filters the plan lists for the
// bounce view specifically: the same free-text and time-range filters, plus
// failure class instead of status.
func (s *Server) handleBounces(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	offset := parseOffset(q.Get("offset"))
	class := q.Get("class")
	filterErrClass := ""
	if class != "" && class != "permanent" && class != "expired" {
		filterErrClass = "class must be permanent or expired"
		class = ""
	}
	filter := store.BounceFilter{
		Sender:    strings.TrimSpace(q.Get("sender")),
		Recipient: strings.TrimSpace(q.Get("recipient")),
		Subject:   strings.TrimSpace(q.Get("subject")),
		Client:    strings.TrimSpace(q.Get("client")),
		Route:     strings.TrimSpace(q.Get("route")),
		Class:     class,
		Limit:     pageSize,
		Offset:    offset,
	}
	filterErr := parseTimeRange(q, &filter.Since, &filter.Until)
	if filterErr == "" {
		filterErr = filterErrClass
	}

	var msgs []*store.Message
	if filterErr == "" {
		var err error
		msgs, err = s.store.FindBounces(filter)
		if err != nil {
			s.serverError(w, "bounces", err)
			return
		}
	}
	s.redactSubjects(msgs)
	hasMore := len(msgs) > pageSize
	if hasMore {
		msgs = msgs[:pageSize]
	}

	extra := filterQueryValues(q, "sender", "recipient", "subject", "client", "route", "class", "since", "until")
	data := struct {
		baseData
		Filter      bounceFilterView
		FilterError string
		Messages    []*store.Message
		HasMore     bool
		NextHref    string
		PrevHref    string
	}{
		baseData: s.base("bounces"),
		Filter: bounceFilterView{
			Sender: filter.Sender, Recipient: filter.Recipient, Subject: filter.Subject,
			Client: filter.Client, Route: filter.Route, Class: filter.Class,
			Since: q.Get("since"), Until: q.Get("until"),
		},
		FilterError: filterErr,
		Messages:    msgs,
		HasMore:     hasMore,
	}
	if hasMore {
		data.NextHref = pageHref("/bounces", extra, "", "", offset+pageSize)
	}
	if offset > 0 {
		data.PrevHref = pageHref("/bounces", extra, "", "", maxInt(0, offset-pageSize))
	}
	s.render(w, "bounces", data)
}

// handleMessage shows one message's full envelope and attempt history. The
// path value is validated through spool.ParseID before it ever reaches a
// query, per the rule that a queue ID is a validated type and never a raw
// string.
func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	id, err := spool.ParseID(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid queue id", http.StatusBadRequest)
		return
	}
	msg, err := s.store.FindMessageByID(id.String())
	if err != nil {
		s.serverError(w, "message", err)
		return
	}
	s.redactSubject(msg)
	data := struct {
		baseData
		Message      *store.Message
		RequeueToken string
		DeleteToken  string
	}{baseData: s.base("message"), Message: msg}
	if msg != nil {
		now := time.Now()
		data.RequeueToken = s.csrf.token("requeue", id.String(), now)
		data.DeleteToken = s.csrf.token("delete", id.String(), now)
	}
	s.render(w, "message", data)
}

// handleRequeueAction moves a message back into the live queue for
// immediate retry. Protected by a CSRF token rather than a bearer token,
// per the phase 4c/4d decision: the dashboard has no session or login to
// authenticate against, so loopback binding plus a per-process CSRF secret
// is its trust boundary, distinct from the JSON API's bearer-token model.
func (s *Server) handleRequeueAction(w http.ResponseWriter, r *http.Request) {
	id, err := spool.ParseID(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid queue id", http.StatusBadRequest)
		return
	}
	if !s.csrf.verify(r.FormValue("csrf"), "requeue", id.String(), time.Now()) {
		http.Error(w, "invalid or expired form token", http.StatusForbidden)
		return
	}
	switch err := s.spool.Requeue(id); {
	case err == nil:
		if aerr := s.store.RecordAudit("dashboard", r.RemoteAddr, "requeue", id.String(), ""); aerr != nil {
			s.log.Warn("audit log write failed", "action", "requeue", "queue_id", id.String(), "error", aerr)
		}
		http.Redirect(w, r, "/messages/"+id.String(), http.StatusSeeOther)
	case errors.Is(err, spool.ErrNotFound):
		http.Error(w, "message not found", http.StatusNotFound)
	case errors.Is(err, spool.ErrBusy):
		http.Error(w, "message is currently being delivered, try again shortly", http.StatusConflict)
	default:
		s.log.Error("requeue failed", "queue_id", id.String(), "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// handleDeleteAction removes a message from the spool, wherever it
// currently sits, while retaining its history row.
func (s *Server) handleDeleteAction(w http.ResponseWriter, r *http.Request) {
	id, err := spool.ParseID(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid queue id", http.StatusBadRequest)
		return
	}
	if !s.csrf.verify(r.FormValue("csrf"), "delete", id.String(), time.Now()) {
		http.Error(w, "invalid or expired form token", http.StatusForbidden)
		return
	}
	switch err := s.spool.Discard(id); {
	case err == nil:
		if aerr := s.store.RecordAudit("dashboard", r.RemoteAddr, "delete", id.String(), ""); aerr != nil {
			s.log.Warn("audit log write failed", "action", "delete", "queue_id", id.String(), "error", aerr)
		}
		http.Redirect(w, r, "/queue", http.StatusSeeOther)
	case errors.Is(err, spool.ErrNotFound):
		http.Error(w, "message not found", http.StatusNotFound)
	case errors.Is(err, spool.ErrBusy):
		http.Error(w, "message is currently being delivered, try again shortly", http.StatusConflict)
	default:
		s.log.Error("delete failed", "queue_id", id.String(), "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (s *Server) handleRoutes(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "routes", s.base("routes"))
}

func (s *Server) handleConfig(w http.ResponseWriter, _ *http.Request) {
	data := struct {
		baseData
		ListenersText string
		ClientsText   string
		RoutesText    string
		BounceText    string
	}{
		baseData:      s.base("config"),
		ListenersText: formatListeners(s.cfg.Listeners),
		ClientsText:   formatClients(s.cfg.Clients),
		RoutesText:    formatRoutes(s.cfg.Routes),
		BounceText:    formatBounce(s.cfg.Bounce),
	}
	s.render(w, "config", data)
}

// parseTimeRange parses the since/until query parameters into *dst, RFC 3339
// only, leaving *dst nil and returning a message on a bad value rather than
// guessing at another layout.
func parseTimeRange(q url.Values, since, until **time.Time) string {
	if v := strings.TrimSpace(q.Get("since")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return "since must be RFC 3339, e.g. 2026-01-01T00:00:00Z"
		}
		*since = &t
	}
	if v := strings.TrimSpace(q.Get("until")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return "until must be RFC 3339, e.g. 2026-01-01T00:00:00Z"
		}
		*until = &t
	}
	return ""
}

func parseOffset(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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
