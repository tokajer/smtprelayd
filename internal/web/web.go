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
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/expiry"
	"github.com/tokajer/smtprelayd/internal/httpx"
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

//go:embed static/style.css
var styleCSS []byte

// htmxJS is vendored, not fetched from a CDN: the dashboard's CSP is
// default-src 'self', and a page reachable only on loopback should not
// depend on an outside host being reachable at all. Version 2.0.4, verified
// against the upstream release before being committed.
//
//go:embed static/htmx.min.js
var htmxJS []byte

// queueJS is the dashboard's only first-party script. It exists because the
// queue's bulk form needs two things no amount of server-rendered HTML can
// provide: a select-all box, and a way to stop the ten-second htmx refresh
// from swapping the table out from under a selection the operator is still
// making -- the same objection that keeps /search's results table out of the
// polling set. It is plain DOM code, event-delegated so it survives a swap,
// and uses neither eval nor inline script, so script-src 'self' still holds.
//
//go:embed static/queue.js
var queueJS []byte

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
	// Load already validated service.timezone; a nil Location here just
	// means every timestamp keeps rendering in whatever zone it already
	// carries (UTC, since that is what the store persists).
	loc, _ := config.ParseTimezone(cfg.Service.Timezone)
	funcs := template.FuncMap{"bytes": formatBytes, "localtime": localtimeFunc(loc)}
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
	// CurrentURL is the request's own path and query, used only as the
	// polling target for htmx: the live regions re-fetch the page they are
	// already on, so sort order, pagination and search filters survive a
	// refresh unchanged.
	CurrentURL string
}

// totals is the sum of the per-route counters already held in memory for the
// header tiles. It deliberately adds no query of its own: the tiles are the
// same numbers /metrics and the route page report, summed.
type totals struct {
	Queued, Deferred int
	Delivered        uint64
	Bounced          uint64
}

func (s *Server) base(page string, r *http.Request) baseData {
	var routes []metrics.RouteStatus
	if s.metrics != nil {
		routes = s.metrics.Status()
	}
	var sum totals
	for _, rt := range routes {
		sum.Queued += rt.Queued
		sum.Deferred += rt.Deferred
		sum.Delivered += rt.Delivered
		sum.Bounced += rt.Bounced
	}
	recent, _, err := s.store.FindBounces(store.BounceFilter{Limit: 5})
	if err != nil {
		s.log.Warn("sidebar: recent bounces query failed", "error", err)
		recent = nil
	}
	return baseData{
		Version: s.version, Page: page, Theme: s.theme,
		Routes: routes, Totals: sum, RecentBounces: recent,
		CurrentURL: r.URL.RequestURI(),
	}
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

func (s *Server) handleHTMXScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = w.Write(htmxJS)
}

func (s *Server) handleQueueScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = w.Write(queueJS)
}

// queueRow is one line of the queue table: a history row plus whether the
// spool still holds the message. The two can disagree -- a message whose
// spool copy is gone while history still calls it queued or deferred stays
// listed here -- and the view has to say so rather than offer the operator a
// requeue that can only ever fail.
type queueRow struct {
	*store.Message
	Stale bool
}

// handleQueue shows messages still in the spool: queued or deferred,
// sortable by the columns the plan calls for, and carries the bulk
// requeue/delete form.
func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sortCol := q.Get("sort")
	order := q.Get("order")
	offset := parseOffset(q.Get("offset"))

	msgs, hasMore, err := s.store.FindMessages(store.MessageFilter{
		Status: "active", Sort: sortCol, Order: order, Limit: pageSize, Offset: offset,
	})
	if err != nil {
		s.serverError(w, "queue", err)
		return
	}
	rows := make([]queueRow, 0, len(msgs))
	for _, m := range msgs {
		row := queueRow{Message: m}
		if id, err := spool.ParseID(m.QueueID); err == nil {
			row.Stale = !s.spool.Has(id)
		}
		rows = append(rows, row)
	}

	now := time.Now()
	data := struct {
		baseData
		Rows      []queueRow
		SortLinks map[string]string
		HasMore   bool
		NextHref  string
		PrevHref  string
		// One token per action, both rendered into the same form: the
		// checkbox set has to be shared, and a <button formaction> picks the
		// endpoint, so the form cannot carry a single field named "csrf"
		// without one action's token authorising the other.
		RequeueToken string
		DeleteToken  string
		Flash        *flash
		// ConfirmDeleteAll renders the interstitial for "delete the whole
		// queue", which is reached as a link rather than a button so that
		// the irreversible action needs a second, deliberate click and stays
		// refresh-safe without any script.
		ConfirmDeleteAll bool
	}{
		baseData:         s.base("queue", r),
		Rows:             rows,
		SortLinks:        sortLinks("/queue", nil, sortCol, order),
		HasMore:          hasMore,
		RequeueToken:     s.csrf.token("queue-requeue", "", now),
		DeleteToken:      s.csrf.token("queue-delete", "", now),
		Flash:            bulkFlash(q),
		ConfirmDeleteAll: q.Get("confirm") == "delete-all",
	}
	data.PrevHref, data.NextHref = pageLinks("/queue", nil, sortCol, order, offset, hasMore)
	s.render(w, "queue", data)
}

// listPage is what every filtered list view binds to. templates/pager.html
// has always been shared between them; this is the Go half of that, so the
// two handlers below differ only in the filter they build and the query they
// run, which is the part that is genuinely different.
//
// Filter is any because each page's form has its own fields, and the template
// reaches them by name. Nothing else here varies.
type listPage struct {
	baseData
	Filter      any
	FilterError string
	Messages    []*store.Message
	HasMore     bool
	NextHref    string
	PrevHref    string
}

// pageLinks is the previous/next arithmetic every paged view repeats. Kept in
// one place because getting it wrong in one view and right in the other is
// invisible until somebody pages past the end.
func pageLinks(path string, extra url.Values, sortCol, order string, offset int, hasMore bool) (prev, next string) {
	if hasMore {
		next = pageHref(path, extra, sortCol, order, offset+pageSize)
	}
	if offset > 0 {
		prev = pageHref(path, extra, sortCol, order, max(0, offset-pageSize))
	}
	return prev, next
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
	filterErr := httpx.ParseTimeRange(q, &filter.Since, &filter.Until)

	var msgs []*store.Message
	var hasMore bool
	if filterErr == "" {
		var err error
		msgs, hasMore, err = s.store.FindMessages(filter)
		if err != nil {
			s.serverError(w, "search", err)
			return
		}
	}

	extra := filterQueryValues(q, "sender", "recipient", "subject", "client", "route", "status", "since", "until")
	data := listPage{
		baseData: s.base("search", r),
		Filter: searchFilterView{
			Sender: filter.Sender, Recipient: filter.Recipient, Subject: filter.Subject,
			Client: filter.Client, Route: filter.Route, Status: filter.Status,
			Since: q.Get("since"), Until: q.Get("until"),
		},
		FilterError: filterErr,
		Messages:    msgs,
		HasMore:     hasMore,
	}
	data.PrevHref, data.NextHref = pageLinks("/search", extra, "", "", offset, hasMore)
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
	filterErr := httpx.ParseTimeRange(q, &filter.Since, &filter.Until)
	if filterErr == "" {
		filterErr = filterErrClass
	}

	var msgs []*store.Message
	var hasMore bool
	if filterErr == "" {
		var err error
		msgs, hasMore, err = s.store.FindBounces(filter)
		if err != nil {
			s.serverError(w, "bounces", err)
			return
		}
	}

	extra := filterQueryValues(q, "sender", "recipient", "subject", "client", "route", "class", "since", "until")
	data := listPage{
		baseData: s.base("bounces", r),
		Filter: bounceFilterView{
			Sender: filter.Sender, Recipient: filter.Recipient, Subject: filter.Subject,
			Client: filter.Client, Route: filter.Route, Class: filter.Class,
			Since: q.Get("since"), Until: q.Get("until"),
		},
		FilterError: filterErr,
		Messages:    msgs,
		HasMore:     hasMore,
	}
	data.PrevHref, data.NextHref = pageLinks("/bounces", extra, "", "", offset, hasMore)
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
	data := struct {
		baseData
		Message      *store.Message
		RequeueToken string
		DeleteToken  string
	}{baseData: s.base("message", r), Message: msg}
	if msg != nil {
		now := time.Now()
		data.RequeueToken = s.csrf.token("requeue", id.String(), now)
		data.DeleteToken = s.csrf.token("delete", id.String(), now)
	}
	s.render(w, "message", data)
}

// actionOutcome is what a requeue or delete did to one message, so that the
// single-message handlers can map it onto a status code while the bulk
// handlers count it. Keeping one description of the outcome is what stops
// the two entry points from drifting apart on, say, a message whose spool
// copy is already gone.
type actionOutcome int

const (
	outcomeDone    actionOutcome = iota // the spool copy was requeued or discarded
	outcomeCleared                      // delete only: no spool copy left, history reconciled
	outcomeBusy                         // leased by a delivery worker
	outcomeMissing                      // nothing to act on, in the spool or in history
	outcomeError                        // logged; the operator gets a 500 or a failure count
)

func (s *Server) audit(r *http.Request, action string, id spool.ID, details string) {
	if err := s.store.RecordAudit("dashboard", r.RemoteAddr, action, id.String(), details); err != nil {
		s.log.Warn("audit log write failed", "action", action, "queue_id", id.String(), "error", err)
	}
}

// requeueMessage moves one message back into the live queue for immediate
// retry. A message whose spool copy is gone cannot be requeued -- there is
// no body to send -- so unlike deleteMessage this has nothing to reconcile
// and reports it as missing.
func (s *Server) requeueMessage(r *http.Request, id spool.ID, details string) actionOutcome {
	switch err := s.spool.Requeue(id); {
	case err == nil:
		s.audit(r, "requeue", id, details)
		return outcomeDone
	case errors.Is(err, spool.ErrNotFound):
		return outcomeMissing
	case errors.Is(err, spool.ErrBusy):
		return outcomeBusy
	default:
		s.log.Error("requeue failed", "queue_id", id.String(), "error", err)
		return outcomeError
	}
}

// deleteMessage removes one message from the spool, wherever it currently
// sits, while retaining its history row.
//
// The ErrNotFound branch is the one that matters: a message can be listed by
// the queue view with no spool copy behind it (a startup recovery dropped a
// half-written pair, an operator deleted the files by hand, a crash landed
// between the unlink and the attempt row). Refusing with 404 there left the
// row in the view permanently, with no action able to clear it, so the
// history is reconciled instead -- which is exactly what the operator asked
// for, "get this out of my queue".
//
// This cannot mislabel a message that was in fact delivered: the delivery
// worker records the "delivered" attempt before it unlinks the body, and a
// leased message answers ErrBusy here rather than reaching this branch, so
// the only way in is a message with no lease, no files and a history row
// that still calls it active. ReconcileRemoved re-checks that last part
// itself and writes nothing otherwise.
func (s *Server) deleteMessage(r *http.Request, id spool.ID, details string) actionOutcome {
	switch err := s.spool.Discard(id); {
	case err == nil:
		if rerr := s.store.RecordRemoval(id.String()); rerr != nil {
			s.log.Warn("removal record write failed", "queue_id", id.String(), "error", rerr)
		}
		s.audit(r, "delete", id, details)
		return outcomeDone
	case errors.Is(err, spool.ErrNotFound):
		cleared, rerr := s.store.ReconcileRemoved(id.String())
		if rerr != nil {
			s.log.Error("reconciling a message with no spool copy failed", "queue_id", id.String(), "error", rerr)
			return outcomeError
		}
		if !cleared {
			return outcomeMissing
		}
		s.log.Info("queue entry cleared for a message with no spool copy",
			"queue_id", id.String(), "source", r.RemoteAddr)
		s.audit(r, "delete", id, joinDetails(details, "no spool copy: history reconciled"))
		return outcomeCleared
	case errors.Is(err, spool.ErrBusy):
		return outcomeBusy
	default:
		s.log.Error("delete failed", "queue_id", id.String(), "error", err)
		return outcomeError
	}
}

func joinDetails(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
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
	switch s.requeueMessage(r, id, "") {
	case outcomeDone:
		//#nosec G710 -- the destination is a fixed path plus a spool.ID that ParseID already validated; nothing from the request reaches it
		http.Redirect(w, r, "/messages/"+id.String(), http.StatusSeeOther)
	case outcomeMissing:
		http.Error(w, "message not found", http.StatusNotFound)
	case outcomeBusy:
		http.Error(w, "message is currently being delivered, try again shortly", http.StatusConflict)
	default:
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
	switch s.deleteMessage(r, id, "") {
	case outcomeDone, outcomeCleared:
		http.Redirect(w, r, "/queue", http.StatusSeeOther)
	case outcomeMissing:
		http.Error(w, "message not found", http.StatusNotFound)
	case outcomeBusy:
		http.Error(w, "message is currently being delivered, try again shortly", http.StatusConflict)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// expiryRow is one deadline as the configuration page renders it. The state
// drives the pill colour and is derived here rather than in the template, so
// the threshold stays the one internal/expiry actually mails on.
type expiryRow struct {
	What    string
	Detail  string
	Expires time.Time
	Days    int
	State   string // ok, soon, expired
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	s.render(w, "routes", s.base("routes", r))
}

// expiryRows renders what is going to stop working. It lists every deadline,
// not only the ones inside the warning window: an operator checking whether
// the certificate is healthy needs to see it while it still is.
func (s *Server) expiryRows(now time.Time) (rows []expiryRow, certErr string) {
	items, err := expiry.Items(s.cfg)
	if err != nil {
		certErr = err.Error()
	}
	window := expiry.WarnWindow(s.cfg)
	for _, it := range items {
		row := expiryRow{
			What: it.What, Detail: it.Detail, Expires: it.Expires,
			Days: expiry.DaysUntil(it.Expires, now), State: "ok",
		}
		switch {
		case !it.Expires.After(now):
			row.State = "expired"
		case window > 0 && it.Expires.Before(now.Add(window)):
			row.State = "soon"
		}
		rows = append(rows, row)
	}
	return rows, certErr
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	rows, certErr := s.expiryRows(time.Now())
	data := struct {
		baseData
		Expiry        []expiryRow
		ExpiryError   string
		WarnDays      int
		ListenersText string
		ClientsText   string
		RoutesText    string
		BounceText    string
	}{
		baseData:      s.base("config", r),
		Expiry:        rows,
		ExpiryError:   certErr,
		WarnDays:      s.cfg.Expiry.WarnDays,
		ListenersText: formatListeners(s.cfg.Listeners),
		ClientsText:   formatClients(s.cfg.Clients),
		RoutesText:    formatRoutes(s.cfg.Routes),
		BounceText:    formatBounce(s.cfg.Bounce),
	}
	s.render(w, "config", data)
}
