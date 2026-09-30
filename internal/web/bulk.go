// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/httpx"
	"github.com/tokajer/smtprelayd/internal/queueaction"
	"github.com/tokajer/smtprelayd/internal/queueid"
	"github.com/tokajer/smtprelayd/internal/store"
)

// The queue page's bulk actions: applying one action to a set of messages,
// bounding how much irreversible work one request may do, and reporting how
// far it got. The per-message primitives they drive (requeueMessage,
// deleteMessage) live in actions.go, where the single-message endpoints use
// them too.

// bulkMax bounds one bulk action. It is store.MaxPageLimit rather than a
// number of its own: FindMessages caps its own result there whatever it is
// asked for, so "everything in the queue" processes at most that many per
// submission and says that more remain. Written as a literal, raising it here
// would change nothing and the constant would stop describing what happens.
// The same ceiling is applied to an explicit selection so that a hand-built
// request cannot ask for unbounded work on the request goroutine.
const bulkMax = store.MaxPageLimit

// bulkBudget bounds how long one bulk action spends on the request
// goroutine. It is half the server's WriteTimeout (internal/web/http.go), so
// the redirect that reports what happened is still written: past that
// deadline the response is cut off mid-flight and the operator is left not
// knowing how much of an irreversible action completed.
//
// Stopping early is reported exactly like hitting bulkMax, because the
// operator does the same thing in both cases -- repeat it.
const bulkBudget = 30 * time.Second

// bulkCounts is the outcome of one bulk action, counted per message.
type bulkCounts struct {
	OK      int
	Cleared int
	Busy    int
	Missing int
	Failed  int
	// Truncated says the action covered only part of what was asked and has
	// to be repeated: either the queue held more than bulkMax active
	// messages, or bulkBudget ran out before the rest could be processed.
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
	s.handleQueueBulk(w, r, requeueAction)
}

func (s *Server) handleQueueDelete(w http.ResponseWriter, r *http.Request) {
	s.handleQueueBulk(w, r, deleteAction)
}

// handleQueueBulk applies one action to a set of messages: either the rows
// the operator ticked, or every message the queue view currently lists.
func (s *Server) handleQueueBulk(w http.ResponseWriter, r *http.Request, a messageAction) {
	// PostFormValue, not FormValue: the token and the selection must come
	// from the submitted body, so a bare GET-shaped link carrying the same
	// parameters cannot drive a bulk action.
	if !s.csrf.verify(r.PostFormValue("csrf_"+a.name), "queue-"+a.name, "", time.Now()) {
		http.Error(w, "invalid or expired form token", http.StatusForbidden)
		return
	}

	scope := r.PostFormValue("scope")
	ids, truncated, ok := s.bulkTargets(w, r, a, scope)
	if !ok {
		return
	}
	res := bulkCounts{Truncated: truncated}

	details := "bulk (" + scope + ")"
	deadline := time.Now().Add(bulkBudget)
	for _, id := range ids {
		// Two reasons to stop: the operator's connection has gone, so the
		// remaining irreversible work benefits nobody; or the budget is
		// spent, and continuing would cost the report of what was already
		// done. Each message is finished before the check, so nothing is
		// left half-applied.
		if r.Context().Err() != nil || time.Now().After(deadline) {
			res.Truncated = true
			break
		}
		switch a.apply(s, r, id, details) {
		case queueaction.Done:
			res.OK++
		case queueaction.Cleared:
			res.Cleared++
		case queueaction.Busy:
			res.Busy++
		case queueaction.Missing:
			res.Missing++
		default:
			res.Failed++
		}
	}
	// Logged whatever happens to the response: if the budget ran out or the
	// operator navigated away, this line is the only record of how far an
	// irreversible action got.
	s.log.Info("bulk queue action", "action", a.name, "scope", scope, "source", httpx.SourceAddr(r),
		"ok", res.OK, "cleared", res.Cleared, "busy", res.Busy, "missing", res.Missing,
		"failed", res.Failed, "incomplete", res.Truncated)

	http.Redirect(w, r, "/queue?"+res.query(a.name).Encode(), http.StatusSeeOther)
}

// bulkTargets resolves which queue IDs a bulk action should act on: either
// the rows the operator ticked, or every message the queue view currently
// lists. It writes the HTTP error itself and reports ok=false when the
// request cannot be satisfied, so the caller only has to check ok.
//
// "All" is resolved from the history store rather than from the spool index
// because the queue view is what the operator is looking at when they ask
// for it, and the two can differ -- a message with no spool copy is listed
// there and is precisely the kind of entry that needs clearing.
func (s *Server) bulkTargets(w http.ResponseWriter, r *http.Request, a messageAction, scope string) (ids []queueid.ID, truncated bool, ok bool) {
	switch scope {
	case "selected":
		selected := r.PostForm["id"]
		if len(selected) > bulkMax {
			http.Error(w, "too many messages selected", http.StatusBadRequest)
			return nil, false, false
		}
		ids = make([]queueid.ID, 0, len(selected))
		for _, v := range selected {
			id, err := queueid.Parse(v)
			if err != nil {
				http.Error(w, "invalid queue id", http.StatusBadRequest)
				return nil, false, false
			}
			ids = append(ids, id)
		}
		return ids, false, true
	case "all":
		// Emptying the whole queue is irreversible, so the form that can do
		// it is only rendered behind the confirmation interstitial. This is
		// belt and braces for a request built by hand.
		if a.confirmAll && r.PostFormValue("confirm") != "delete-all" {
			http.Error(w, "deleting the whole queue must be confirmed", http.StatusBadRequest)
			return nil, false, false
		}
		var err error
		ids, truncated, err = s.activeQueueIDs()
		if err != nil {
			s.serverError(w, "queue", err)
			return nil, false, false
		}
		return ids, truncated, true
	default:
		http.Error(w, "scope must be selected or all", http.StatusBadRequest)
		return nil, false, false
	}
}

// activeQueueIDs lists the queue IDs the queue view currently shows, capped
// at bulkMax with a flag saying the cap was hit.
func (s *Server) activeQueueIDs() ([]queueid.ID, bool, error) {
	// hasMore is the cap signal: the store fetches one row past the limit to
	// answer it, which is exactly "there were more than bulkMax active
	// messages" -- and the caller has to say so, because a bulk action that
	// silently covered part of the queue is the wrong kind of surprise.
	msgs, truncated, err := s.store.FindMessages(store.MessageFilter{Status: store.StatusActive, Limit: bulkMax})
	if err != nil {
		return nil, false, err
	}
	ids := make([]queueid.ID, 0, len(msgs))
	for _, m := range msgs {
		ids = append(ids, m.QueueID)
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
		OK:        parseNonNegative(q.Get("ok")),
		Cleared:   parseNonNegative(q.Get("cleared")),
		Busy:      parseNonNegative(q.Get("busy")),
		Missing:   parseNonNegative(q.Get("missing")),
		Failed:    parseNonNegative(q.Get("failed")),
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
		text += " Not every message was covered; repeat the action to continue."
	}
	level := "ok"
	if c.Busy > 0 || c.Missing > 0 || c.Failed > 0 {
		level = "warn"
	}
	return &flash{Level: level, Text: text}
}
