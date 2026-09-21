// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/expiry"
	"github.com/tokajer/smtprelayd/internal/httpx"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// The dashboard's read-only pages: the live queue, search, bounces, one
// message, route status and the configuration view. Everything that changes
// state lives in actions.go.

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
