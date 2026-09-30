// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"net/http"
	"time"

	"github.com/tokajer/smtprelayd/internal/httpx"
	"github.com/tokajer/smtprelayd/internal/queueaction"
	"github.com/tokajer/smtprelayd/internal/queueid"
)

// The dashboard's state-changing actions: requeue and delete, for one
// message and, through bulk.go, for a set of them. The pages that render the
// forms are in pages.go; what a CSRF token protects and why the dashboard
// has no login is in csrf.go.

// What requeue and delete mean for a message, and what to do when its spool
// copy is gone, live in internal/queueaction: the JSON API makes exactly the
// same decisions and the two must not drift apart. What stays here is how an
// outcome becomes a redirect, a status code or a tally.

// requeueMessage and deleteMessage name the acting party for the audit row.
// The dashboard has no login, so every action it takes is "dashboard"; the
// JSON API passes its token's name instead.
func (s *Server) requeueMessage(r *http.Request, id queueid.ID, details string) queueaction.Outcome {
	return s.actions.Requeue(id, "dashboard", httpx.SourceAddr(r), details)
}

func (s *Server) deleteMessage(r *http.Request, id queueid.ID, details string) queueaction.Outcome {
	return s.actions.Delete(id, "dashboard", httpx.SourceAddr(r), details)
}

// messageAction is one of the two actions the message detail page and the
// queue page's bulk form both offer, kept as one type so a change to one of
// its fields cannot drift out of step between the two forms.
type messageAction struct {
	// name is the CSRF action the single-message form's token is scoped to
	// (bound to the queue ID as well, so a token for one message cannot act
	// on another; see csrf.go), and, as "queue-"+name, the bulk form's. It
	// also names the bulk form's csrf_<name> field and the redirect's
	// ?done= parameter that bulkFlash reads back.
	name string

	apply func(*Server, *http.Request, queueid.ID, string) queueaction.Outcome

	// redirect names where a successful single-message action sends the
	// operator. The bulk path ignores it: it always redirects to /queue with
	// the tallied outcome instead.
	redirect func(queueid.ID) string

	// confirmAll marks a bulk action whose "all" scope is irreversible and so
	// needs the confirmation interstitial's own field as well as the CSRF
	// token. Meaningless for a single-message action, which always names one
	// message.
	confirmAll bool
}

var (
	requeueAction = messageAction{
		name: "requeue", apply: (*Server).requeueMessage,
		redirect: func(id queueid.ID) string { return "/messages/" + id.String() },
	}
	deleteAction = messageAction{
		name: "delete", confirmAll: true, apply: (*Server).deleteMessage,
		// Back to the queue rather than to a message that is no longer
		// there to render.
		redirect: func(queueid.ID) string { return "/queue" },
	}
)

// handleRequeueAction moves a message back into the live queue for
// immediate retry. Protected by a CSRF token rather than a bearer token,
// per the phase 4c/4d decision: the dashboard has no session or login to
// authenticate against, so loopback binding plus a per-process CSRF secret
// is its trust boundary, distinct from the JSON API's bearer-token model.
func (s *Server) handleRequeueAction(w http.ResponseWriter, r *http.Request) {
	s.handleMessageAction(w, r, requeueAction)
}

// handleDeleteAction removes a message from the spool, wherever it
// currently sits, while retaining its history row.
func (s *Server) handleDeleteAction(w http.ResponseWriter, r *http.Request) {
	s.handleMessageAction(w, r, deleteAction)
}

func (s *Server) handleMessageAction(w http.ResponseWriter, r *http.Request, a messageAction) {
	id, err := queueid.Parse(r.PathValue("id"))
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
		//#nosec G710 -- the destination is a fixed path plus a queueid.ID that Parse already validated; nothing from the request reaches it
		http.Redirect(w, r, a.redirect(id), http.StatusSeeOther)
	case queueaction.Missing:
		http.Error(w, "message not found", http.StatusNotFound)
	case queueaction.Busy:
		http.Error(w, "message is currently being delivered, try again shortly", http.StatusConflict)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
