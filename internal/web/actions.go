// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"net/http"
	"time"

	"github.com/tokajer/smtprelayd/internal/httpx"
	"github.com/tokajer/smtprelayd/internal/queueaction"
	"github.com/tokajer/smtprelayd/internal/spool"
)

// The dashboard's state-changing actions: requeue and delete, for one
// message and, through bulk.go, for a set of them. The pages that render the
// forms are in pages.go; what a CSRF token protects and why the dashboard
// has no login is in csrf.go.

// What requeue and delete mean for a message, and what to do when its spool
// copy is gone, live in internal/queueaction: the JSON API makes exactly the
// same decisions and the two must not drift apart. What stays here is how an
// outcome becomes a redirect, a status code or a tally.
//
// The outcomes are named as queueaction.Done and so on rather than aliased
// into a local vocabulary. The aliases read a little shorter here and cost a
// reader of bulk.go two names for one enum, which is the worse trade for five
// constants that are only ever switched on.

// requeueMessage and deleteMessage name the acting party for the audit row.
// The dashboard has no login, so every action it takes is "dashboard"; the
// JSON API passes its token's name instead.
func (s *Server) requeueMessage(r *http.Request, id spool.ID, details string) queueaction.Outcome {
	return s.actions.Requeue(id, "dashboard", httpx.SourceAddr(r), details)
}

func (s *Server) deleteMessage(r *http.Request, id spool.ID, details string) queueaction.Outcome {
	return s.actions.Delete(id, "dashboard", httpx.SourceAddr(r), details)
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
	case queueaction.Done:
		//#nosec G710 -- the destination is a fixed path plus a spool.ID that ParseID already validated; nothing from the request reaches it
		http.Redirect(w, r, "/messages/"+id.String(), http.StatusSeeOther)
	case queueaction.Missing:
		http.Error(w, "message not found", http.StatusNotFound)
	case queueaction.Busy:
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
	case queueaction.Done, queueaction.Cleared:
		http.Redirect(w, r, "/queue", http.StatusSeeOther)
	case queueaction.Missing:
		http.Error(w, "message not found", http.StatusNotFound)
	case queueaction.Busy:
		http.Error(w, "message is currently being delivered, try again shortly", http.StatusConflict)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
