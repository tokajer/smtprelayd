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

// messageAction is one of the two actions the message detail page offers.
// The two handlers were the same twenty lines twice -- parse the id, verify
// the CSRF token, switch on the outcome -- differing only in the CSRF action
// name, which primitive they call and where a success redirects to. A value
// carries those three, the way bulkAction does for the queue page's set
// actions.
type messageAction struct {
	// name is the CSRF action the form's token is scoped to. It is bound to
	// the queue ID as well, so a token for one message cannot act on
	// another; see csrf.go.
	name     string
	apply    func(*Server, *http.Request, spool.ID, string) queueaction.Outcome
	redirect func(spool.ID) string
}

var (
	requeueOne = messageAction{
		name: "requeue", apply: (*Server).requeueMessage,
		redirect: func(id spool.ID) string { return "/messages/" + id.String() },
	}
	deleteOne = messageAction{
		name: "delete", apply: (*Server).deleteMessage,
		// Back to the queue rather than to a message that is no longer
		// there to render.
		redirect: func(spool.ID) string { return "/queue" },
	}
)

// handleRequeueAction moves a message back into the live queue for
// immediate retry. Protected by a CSRF token rather than a bearer token,
// per the phase 4c/4d decision: the dashboard has no session or login to
// authenticate against, so loopback binding plus a per-process CSRF secret
// is its trust boundary, distinct from the JSON API's bearer-token model.
func (s *Server) handleRequeueAction(w http.ResponseWriter, r *http.Request) {
	s.handleMessageAction(w, r, requeueOne)
}

// handleDeleteAction removes a message from the spool, wherever it
// currently sits, while retaining its history row.
func (s *Server) handleDeleteAction(w http.ResponseWriter, r *http.Request) {
	s.handleMessageAction(w, r, deleteOne)
}

func (s *Server) handleMessageAction(w http.ResponseWriter, r *http.Request, a messageAction) {
	id, err := spool.ParseID(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid queue id", http.StatusBadRequest)
		return
	}
	if !s.csrf.verify(r.FormValue("csrf"), a.name, id.String(), time.Now()) {
		http.Error(w, "invalid or expired form token", http.StatusForbidden)
		return
	}
	switch a.apply(s, r, id, "") {
	// Cleared is delete's alone -- there was no spool copy and the history
	// row was reconciled -- and queueaction.Requeue cannot produce it, since
	// a message with no body cannot be requeued. Both are a success for the
	// operator, so both redirect.
	case queueaction.Done, queueaction.Cleared:
		//#nosec G710 -- the destination is a fixed path plus a spool.ID that ParseID already validated; nothing from the request reaches it
		http.Redirect(w, r, a.redirect(id), http.StatusSeeOther)
	case queueaction.Missing:
		http.Error(w, "message not found", http.StatusNotFound)
	case queueaction.Busy:
		http.Error(w, "message is currently being delivered, try again shortly", http.StatusConflict)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
