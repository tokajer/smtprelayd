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

// bulkMax bounds one bulk action. store.FindMessages caps its own result at
// 1000 rows, so "everything in the queue" processes at most that many per
// submission and says that more remain; the same ceiling is applied to an
// explicit selection so that a hand-built request cannot ask for unbounded
// work on the request goroutine.
const bulkMax = 1000

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
		CurrentURL: r.URL.RequestURI(),
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

// bulkCounts is the outcome of one bulk action, counted per message.
type bulkCounts struct {
	OK      int
	Cleared int
	Busy    int
	Missing int
	Failed  int
	// Truncated says the queue held more than bulkMax active messages, so
	// the action covered a prefix of it and has to be repeated.
	Truncated bool
}

// flash is the one-line outcome banner the queue page renders after a bulk
// action. It is rebuilt from the redirect's query string rather than kept in
// server-side state, so a reload cannot repeat the action and there is no
// session to hold.
type flash struct {
	Level string // "ok" or "warn"
	Text  string
}

func (s *Server) handleQueueRequeue(w http.ResponseWriter, r *http.Request) {
	s.handleQueueBulk(w, r, "requeue")
}

func (s *Server) handleQueueDelete(w http.ResponseWriter, r *http.Request) {
	s.handleQueueBulk(w, r, "delete")
}

// handleQueueBulk applies one action to a set of messages: either the rows
// the operator ticked, or every message the queue view currently lists.
//
// "All" is resolved from the history store rather than from the spool index
// because the queue view is what the operator is looking at when they ask
// for it, and the two can differ -- a message with no spool copy is listed
// there and is precisely the kind of entry that needs clearing.
func (s *Server) handleQueueBulk(w http.ResponseWriter, r *http.Request, action string) {
	// PostFormValue, not FormValue: the token and the selection must come
	// from the submitted body, so a bare GET-shaped link carrying the same
	// parameters cannot drive a bulk action.
	if !s.csrf.verify(r.PostFormValue("csrf_"+action), "queue-"+action, "", time.Now()) {
		http.Error(w, "invalid or expired form token", http.StatusForbidden)
		return
	}

	var (
		ids   []spool.ID
		res   bulkCounts
		scope = r.PostFormValue("scope")
	)
	switch scope {
	case "selected":
		selected := r.PostForm["id"]
		if len(selected) > bulkMax {
			http.Error(w, "too many messages selected", http.StatusBadRequest)
			return
		}
		ids = make([]spool.ID, 0, len(selected))
		for _, v := range selected {
			id, err := spool.ParseID(v)
			if err != nil {
				http.Error(w, "invalid queue id", http.StatusBadRequest)
				return
			}
			ids = append(ids, id)
		}
	case "all":
		// Emptying the whole queue is irreversible, so the form that can do
		// it is only rendered behind the confirmation interstitial. This is
		// belt and braces for a request built by hand.
		if action == "delete" && r.PostFormValue("confirm") != "delete-all" {
			http.Error(w, "deleting the whole queue must be confirmed", http.StatusBadRequest)
			return
		}
		var err error
		ids, res.Truncated, err = s.activeQueueIDs()
		if err != nil {
			s.serverError(w, "queue", err)
			return
		}
	default:
		http.Error(w, "scope must be selected or all", http.StatusBadRequest)
		return
	}

	details := "bulk (" + scope + ")"
	for _, id := range ids {
		var outcome actionOutcome
		if action == "requeue" {
			outcome = s.requeueMessage(r, id, details)
		} else {
			outcome = s.deleteMessage(r, id, details)
		}
		switch outcome {
		case outcomeDone:
			res.OK++
		case outcomeCleared:
			res.Cleared++
		case outcomeBusy:
			res.Busy++
		case outcomeMissing:
			res.Missing++
		default:
			res.Failed++
		}
	}
	s.log.Info("bulk queue action", "action", action, "scope", scope, "source", r.RemoteAddr,
		"ok", res.OK, "cleared", res.Cleared, "busy", res.Busy, "missing", res.Missing, "failed", res.Failed)

	http.Redirect(w, r, "/queue?"+res.query(action).Encode(), http.StatusSeeOther)
}

// activeQueueIDs lists the queue IDs the queue view currently shows, capped
// at bulkMax with a flag saying the cap was hit.
func (s *Server) activeQueueIDs() ([]spool.ID, bool, error) {
	msgs, err := s.store.FindMessages(store.MessageFilter{Status: "active", Limit: bulkMax})
	if err != nil {
		return nil, false, err
	}
	truncated := len(msgs) > bulkMax
	if truncated {
		msgs = msgs[:bulkMax]
	}
	ids := make([]spool.ID, 0, len(msgs))
	for _, m := range msgs {
		id, err := spool.ParseID(m.QueueID)
		if err != nil {
			// Nothing the listener writes can produce this; a row that
			// cannot name a spool file is skipped rather than failing the
			// whole action for the rows that can.
			s.log.Warn("queue row skipped: queue id does not parse", "error", err)
			continue
		}
		ids = append(ids, id)
	}
	return ids, truncated, nil
}

// query encodes the counts for the redirect back to /queue. Every value is
// an integer this process just counted and every key is a literal, so the
// banner is rebuilt from numbers, never from text that came in with the
// request.
func (c bulkCounts) query(action string) url.Values {
	v := url.Values{}
	v.Set("done", action)
	for key, n := range map[string]int{
		"ok": c.OK, "cleared": c.Cleared, "busy": c.Busy, "missing": c.Missing, "failed": c.Failed,
	} {
		if n > 0 {
			v.Set(key, strconv.Itoa(n))
		}
	}
	if c.Truncated {
		v.Set("more", "1")
	}
	return v
}

// bulkFlash rebuilds the outcome banner from the redirect's query string. An
// unknown action yields no banner at all, so a crafted link cannot put an
// arbitrary sentence on the page; the numbers are parsed, not echoed.
func bulkFlash(q url.Values) *flash {
	action := q.Get("done")
	var verb string
	switch action {
	case "requeue":
		verb = "requeued"
	case "delete":
		verb = "deleted"
	default:
		return nil
	}

	c := bulkCounts{
		OK:        parseOffset(q.Get("ok")),
		Cleared:   parseOffset(q.Get("cleared")),
		Busy:      parseOffset(q.Get("busy")),
		Missing:   parseOffset(q.Get("missing")),
		Failed:    parseOffset(q.Get("failed")),
		Truncated: q.Get("more") == "1",
	}

	var parts []string
	if c.OK > 0 {
		parts = append(parts, fmt.Sprintf("%d %s", c.OK, verb))
	}
	if c.Cleared > 0 {
		parts = append(parts, fmt.Sprintf("%d had no spool copy left and were cleared from the queue view", c.Cleared))
	}
	if c.Busy > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped, currently being delivered", c.Busy))
	}
	if c.Missing > 0 {
		parts = append(parts, fmt.Sprintf("%d no longer in the queue", c.Missing))
	}
	if c.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed, see the log", c.Failed))
	}
	if len(parts) == 0 {
		return &flash{Level: "warn", Text: "No message was selected, so nothing was " + verb + "."}
	}

	text := strings.Join(parts, ", ") + "."
	if c.Truncated {
		text += fmt.Sprintf(" The queue held more than %d messages; repeat the action to continue.", bulkMax)
	}
	level := "ok"
	if c.Busy > 0 || c.Missing > 0 || c.Failed > 0 {
		level = "warn"
	}
	return &flash{Level: level, Text: text}
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	s.render(w, "routes", s.base("routes", r))
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	data := struct {
		baseData
		ListenersText string
		ClientsText   string
		RoutesText    string
		BounceText    string
	}{
		baseData:      s.base("config", r),
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
