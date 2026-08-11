// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package api

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// parseTimeRangeQuery parses the since/until query parameters into *since
// and *until, RFC 3339 only. It returns a message on a bad value instead of
// guessing at another layout; an empty return means both parsed cleanly (or
// were absent).
func parseTimeRangeQuery(q url.Values, since, until **time.Time) string {
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

func limitFromQuery(q url.Values, fallback int) int {
	n, err := strconv.Atoi(q.Get("limit"))
	if err != nil || n <= 0 || n > maxLimit {
		return fallback
	}
	return n
}

func splitHasMore[T any](rows []T, limit int) ([]T, bool) {
	if len(rows) > limit {
		return rows[:limit], true
	}
	return rows, false
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
		if rt.Auth == "xoauth2" {
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
	if msg := parseTimeRangeQuery(q, &filter.Since, &filter.Until); msg != "" {
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}

	rows, hasMore, err := s.store.FindBounceSummaries(filter)
	if err != nil {
		s.serverError(w, "bounces", err)
		return
	}
	for i := range rows {
		rows[i].Subject = s.redactSubject(rows[i].Subject)
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

// validMessageStatus allowlists the status values docs/API.md documents for
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
	if msg := parseTimeRangeQuery(q, &filter.Since, &filter.Until); msg != "" {
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}

	rows, err := s.store.FindMessages(filter)
	if err != nil {
		s.serverError(w, "messages", err)
		return
	}
	rows, hasMore := splitHasMore(rows, filter.Limit)
	for _, m := range rows {
		m.Subject = s.redactSubject(m.Subject)
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
	msg.Subject = s.redactSubject(msg.Subject)
	writeJSON(w, http.StatusOK, msg)
}

func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	type routeState struct {
		Route          string     `json:"route"`
		Queued         int        `json:"queued"`
		Deferred       int        `json:"deferred"`
		OldestQueued   *time.Time `json:"oldest_queued,omitempty"`
		DeliveredTotal uint64     `json:"delivered_total"`
		BouncedTotal   uint64     `json:"bounced_total"`
		LastDelivery   *time.Time `json:"last_delivery,omitempty"`
	}

	var routes []routeState
	if s.metrics != nil {
		for _, st := range s.metrics.Status() {
			row := routeState{
				Route: st.Route, Queued: st.Queued, Deferred: st.Deferred,
				DeliveredTotal: st.Delivered, BouncedTotal: st.Bounced,
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
		if aerr := s.store.RecordAudit(tokenName, sourceAddr(r), "requeue", id.String(), ""); aerr != nil {
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
		if aerr := s.store.RecordAudit(tokenName, sourceAddr(r), "delete", id.String(), ""); aerr != nil {
			s.log.Warn("audit log write failed", "action", "delete", "queue_id", id.String(), "error", aerr)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	case errors.Is(err, spool.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "message not found")
	case errors.Is(err, spool.ErrBusy):
		writeJSONError(w, http.StatusConflict, "message is currently being delivered")
	default:
		s.serverError(w, "delete", err)
	}
}
