// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/queueaction"
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

// pageSize bounds how many rows a single dashboard page shows.
//
// It is one of three page sizes in the tree, and they answer three different
// questions, which is why they differ: this one is what fits on a screen
// without scrolling past the sidebar; internal/api's defaultLimit (100) is
// what a client gets when it names no limit of its own; and
// store.MaxPageLimit (1000) is the ceiling every list query is clamped to
// whatever it is asked for, which bulkMax then borrows. Only the last is a
// limit -- the other two are defaults, and neither may exceed it.
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

	// actions carries out requeue and delete. The JSON API holds the same
	// thing, so both entry points cannot disagree about what they mean.
	actions *queueaction.Actor
}

// New parses the embedded templates and builds a dashboard server. cfg, st,
// sp and reg must outlive the server; nothing here mutates them, and reg may
// be nil if metrics are disabled, in which case the route sidebar is empty.
func New(cfg *config.Config, st *store.Store, sp *spool.Spool, reg *metrics.Registry, version string, log *slog.Logger) (*Server, error) {
	tmpl := make(map[string]*template.Template, len(dashboardPages))
	// Load already validated service.timezone; a nil Location here just
	// means every timestamp keeps rendering in whatever zone it already
	// carries (UTC, since that is what the store persists).
	loc, _ := config.ParseTimezone(cfg.Service.Timezone)
	funcs := template.FuncMap{"bytes": formatBytes, "localtime": localtimeFunc(loc)}
	for _, p := range dashboardPages {
		t, err := template.New(p.name).Funcs(funcs).ParseFS(templateFS,
			"templates/layout.html", "templates/sidebar.html", "templates/pager.html",
			"templates/"+p.name+".html")
		if err != nil {
			return nil, fmt.Errorf("web: parse template %s: %w", p.name, err)
		}
		tmpl[p.name] = t
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
		actions: queueaction.New(sp, st, log.With("component", "web")),
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

	// JournalFailures is how many history-store writes have failed since
	// start. Every listing on this dashboard is built from that store, so a
	// message whose row was never written is in the spool and on no page
	// here. The banner it drives is the only place that discrepancy is
	// visible to somebody looking at the queue rather than at the log.
	JournalFailures uint64
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
	var journalFailures uint64
	if s.metrics != nil {
		journalFailures = s.metrics.JournalWriteFailures()
	}
	return baseData{
		Version: s.version, Page: page, Theme: s.theme,
		Routes: routes, Totals: sum, RecentBounces: recent,
		CurrentURL:      r.URL.RequestURI(),
		JournalFailures: journalFailures,
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
