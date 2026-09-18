// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package api

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/httpx"
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

func limitFromQuery(q url.Values, fallback int) int {
	n, err := strconv.Atoi(q.Get("limit"))
	if err != nil || n <= 0 || n > maxLimit {
		return fallback
	}
	return n
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	statusByRoute := map[string]metrics.RouteStatus{}
	if s.metrics != nil {
		for _, st := range s.metrics.Status() {
			statusByRoute[st.Route] = st
		}
	}

	type healthRoute struct {
		Name          string `json:"name"`
		Auth          string `json:"auth"`
		Authenticated bool   `json:"authenticated"`
	}
	routes := make([]healthRoute, 0, len(s.cfg.Routes))
	for _, rt := range s.cfg.Routes {
		authenticated := true
		if rt.Auth == config.AuthXOAUTH2 {
			authenticated = statusByRoute[rt.Name].HasToken
		}
		routes = append(routes, healthRoute{Name: rt.Name, Auth: rt.Auth, Authenticated: authenticated})
	}

	var uptime time.Duration
	if s.metrics != nil {
		uptime = s.metrics.Uptime()
	}

	writeJSON(w, http.StatusOK, struct {
		Status        string        `json:"status"`
		Version       string        `json:"version"`
		UptimeSeconds int64         `json:"uptime_seconds"`
		Routes        []healthRoute `json:"routes"`
	}{Status: "ok", Version: s.version, UptimeSeconds: int64(uptime.Seconds()), Routes: routes})
}

func (s *Server) handleBounces(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c := decodeCursor(q.Get("cursor"))
	c.Limit = limitFromQuery(q, c.Limit)

	class := q.Get("class")
	if class != "" && class != "permanent" && class != "expired" {
		writeJSONError(w, http.StatusBadRequest, "class must be permanent or expired")
		return
	}

	filter := store.BounceFilter{
		Sender: q.Get("sender"), Recipient: q.Get("recipient"), Subject: q.Get("subject"),
		Client: q.Get("client"), Route: q.Get("route"), Class: class,
		Limit: c.Limit, Offset: c.Offset,
	}
	if msg := httpx.ParseTimeRange(q, &filter.Since, &filter.Until); msg != "" {
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}

	rows, hasMore, err := s.store.FindBounceSummaries(filter)
	if err != nil {
		s.serverError(w, "bounces", err)
		return
	}

	resp := struct {
		Bounces    []store.BounceSummary `json:"bounces"`
		NextCursor *string               `json:"next_cursor"`
	}{Bounces: rows}
	if hasMore {
		next := encodeCursor(pageCursor{Offset: c.Offset + c.Limit, Limit: c.Limit})
		resp.NextCursor = &next
	}
	writeJSON(w, http.StatusOK, resp)
}

// validMessageStatus allowlists the status values docs/guides/API.md documents for
// /api/v1/messages. "active" (queued or deferred) is a convenience the web
// dashboard's own /queue view uses internally; it is not part of the
// published API contract, so it is not accepted here.
func validMessageStatus(s string) bool {
	switch s {
	case "", "queued", "deferred", "delivered", "bounced":
		return true
	default:
		return false
	}
}

func (s *Server) handleMessages(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c := decodeCursor(q.Get("cursor"))
	c.Limit = limitFromQuery(q, c.Limit)

	status := q.Get("status")
	if !validMessageStatus(status) {
		writeJSONError(w, http.StatusBadRequest, "status must be queued, deferred, delivered or bounced")
		return
	}

	filter := store.MessageFilter{
		Sender: q.Get("sender"), Recipient: q.Get("recipient"), Subject: q.Get("subject"),
		Client: q.Get("client"), Route: q.Get("route"), Status: status,
		Limit: c.Limit, Offset: c.Offset,
	}
	if msg := httpx.ParseTimeRange(q, &filter.Since, &filter.Until); msg != "" {
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}

	rows, hasMore, err := s.store.FindMessages(filter)
	if err != nil {
		s.serverError(w, "messages", err)
		return
	}

	resp := struct {
		Messages   []*store.Message `json:"messages"`
		NextCursor *string          `json:"next_cursor"`
	}{Messages: rows}
	if hasMore {
		next := encodeCursor(pageCursor{Offset: c.Offset + c.Limit, Limit: c.Limit})
		resp.NextCursor = &next
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	id, err := spool.ParseID(r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid queue id")
		return
	}
	msg, err := s.store.FindMessageByID(id.String())
	if err != nil {
		s.serverError(w, "message", err)
		return
	}
	if msg == nil {
		writeJSONError(w, http.StatusNotFound, "message not found")
		return
	}
	writeJSON(w, http.StatusOK, msg)
}

func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	// Mirrors metrics.RouteStatus field for field, minus the cached-token
	// state /api/v1/health already answers. A counter that exists in the
	// exposition and not here is a route whose state the two disagree
	// about -- and recipients_refused_total is the one that cannot be
	// inferred from the others: a message with a refused recipient is
	// delivered, so it appears in no failure counter at all.
	type routeState struct {
		Route             string     `json:"route"`
		Queued            int        `json:"queued"`
		Deferred          int        `json:"deferred"`
		OldestQueued      *time.Time `json:"oldest_queued,omitempty"`
		DeliveredTotal    uint64     `json:"delivered_total"`
		BouncedTotal      uint64     `json:"bounced_total"`
		DeferredTotal     uint64     `json:"deferred_total"`
		AuthFailuresTotal uint64     `json:"auth_failures_total"`
		RecipientsRefused uint64     `json:"recipients_refused_total"`
		LastDelivery      *time.Time `json:"last_delivery,omitempty"`
	}

	var routes []routeState
	if s.metrics != nil {
		for _, st := range s.metrics.Status() {
			row := routeState{
				Route: st.Route, Queued: st.Queued, Deferred: st.Deferred,
				DeliveredTotal:    st.Delivered,
				BouncedTotal:      st.Bounced,
				DeferredTotal:     st.DeferredTotal,
				AuthFailuresTotal: st.AuthFailures,
				RecipientsRefused: st.RecipientsRefused,
			}
			if !st.OldestQueued.IsZero() {
				t := st.OldestQueued
				row.OldestQueued = &t
			}
			if !st.LastDelivery.IsZero() {
				t := st.LastDelivery
				row.LastDelivery = &t
			}
			routes = append(routes, row)
		}
	}
	writeJSON(w, http.StatusOK, struct {
		Routes []routeState `json:"routes"`
	}{Routes: routes})
}

func (s *Server) handleRequeue(w http.ResponseWriter, r *http.Request) {
	id, err := spool.ParseID(r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid queue id")
		return
	}
	tokenName, _ := r.Context().Value(tokenNameKey{}).(string)
	switch err := s.spool.Requeue(id); {
	case err == nil:
		if aerr := s.store.RecordAudit(tokenName, httpx.SourceAddr(r), "requeue", id.String(), ""); aerr != nil {
			s.log.Warn("audit log write failed", "action", "requeue", "queue_id", id.String(), "error", aerr)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "requeued"})
	case errors.Is(err, spool.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "message not found")
	case errors.Is(err, spool.ErrBusy):
		writeJSONError(w, http.StatusConflict, "message is currently being delivered")
	default:
		s.serverError(w, "requeue", err)
	}
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id, err := spool.ParseID(r.PathValue("id"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid queue id")
		return
	}
	tokenName, _ := r.Context().Value(tokenNameKey{}).(string)
	switch err := s.spool.Discard(id); {
	case err == nil:
		if rerr := s.store.RecordRemoval(id.String()); rerr != nil {
			s.log.Warn("removal record write failed", "queue_id", id.String(), "error", rerr)
		}
		if aerr := s.store.RecordAudit(tokenName, httpx.SourceAddr(r), "delete", id.String(), ""); aerr != nil {
			s.log.Warn("audit log write failed", "action", "delete", "queue_id", id.String(), "error", aerr)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	case errors.Is(err, spool.ErrNotFound):
		// The spool copy is already gone. If history still calls the message
		// queued or deferred it keeps showing up as active in every listing,
		// with nothing able to clear it, so the record is reconciled instead
		// of answering 404 forever. The dashboard's delete does the same;
		// the two entry points must not disagree about what delete means.
		cleared, rerr := s.store.ReconcileRemoved(id.String())
		if rerr != nil {
			s.serverError(w, "delete", rerr)
			return
		}
		if !cleared {
			writeJSONError(w, http.StatusNotFound, "message not found")
			return
		}
		if aerr := s.store.RecordAudit(tokenName, httpx.SourceAddr(r), "delete", id.String(), "no spool copy: history reconciled"); aerr != nil {
			s.log.Warn("audit log write failed", "action", "delete", "queue_id", id.String(), "error", aerr)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
	case errors.Is(err, spool.ErrBusy):
		writeJSONError(w, http.StatusConflict, "message is currently being delivered")
	default:
		s.serverError(w, "delete", err)
	}
}
