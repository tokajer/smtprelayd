// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package selfmail spools mail the relay composed itself rather than
// accepted from a client: bounce digests, expiry warnings, canary probes.
//
// All three need the same four steps -- render a header block, spool the
// message, record it in the history journal, return the queue ID -- and each
// had its own copy of them. One copy means the journal metadata cannot
// disagree between them, and it is the only place that knows a
// relay-composed message never passes through the listener and so is never
// subject to sender rewriting.
package selfmail

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/rewrite"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// ContentType is what every relay-composed message declares. It is written
// into both the header block and the journal record, so the two cannot
// disagree about what was sent.
const ContentType = "text/plain; charset=utf-8"

// Message is one message the relay wrote itself.
type Message struct {
	// HeaderFrom is what the From: header says. It is deliberately separate
	// from EnvelopeFrom: a notification carries a readable From so a person
	// can see who sent it, while its reverse path stays empty.
	HeaderFrom string

	// EnvelopeFrom is the reverse path. Empty is the null reverse path,
	// which net/smtp renders as "MAIL FROM:<>" -- what a notification uses so
	// that a failure to deliver it cannot produce another notification.
	EnvelopeFrom string

	To      []string
	Subject string
	Body    string

	// Client is the history journal's grouping key, and for a canary also
	// what internal/bounce groups digest entries by.
	Client   string
	Route    string
	Listener string

	// Notification keeps the delivery manager from treating this message's
	// own failure as another bounce to report. Canary sets it false on
	// purpose: a failing canary is exactly what should reach the digest.
	Notification bool
	Canary       bool
}

// Enqueue renders msg, spools it and records it in the journal. The journal
// write is best-effort: a message that is queued but unrecorded still gets
// delivered, whereas failing here would lose it.
func Enqueue(sp *spool.Spool, st *store.Store, log *slog.Logger, msg Message, lifetime time.Duration, now time.Time) (spool.ID, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", msg.HeaderFrom)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(msg.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", msg.Subject)
	fmt.Fprintf(&b, "Date: %s\r\n", now.Format(time.RFC1123Z))
	b.WriteString("Content-Type: " + ContentType + "\r\n\r\n")
	b.WriteString(msg.Body)
	data := b.String()

	env := spool.Envelope{
		From:         msg.EnvelopeFrom,
		To:           msg.To,
		Client:       msg.Client,
		Route:        msg.Route,
		Listener:     msg.Listener,
		RemoteAddr:   "internal",
		Received:     now,
		Notification: msg.Notification,
		Canary:       msg.Canary,
	}
	// maxBytes 0 is "no limit": these are a few kilobytes the relay wrote
	// itself, not client input to bound.
	id, err := sp.Enqueue(env, strings.NewReader(data), 0, lifetime)
	if err != nil {
		return "", fmt.Errorf("selfmail: enqueue: %w", err)
	}

	recipientsJSON, _ := json.Marshal(msg.To)
	if rerr := st.RecordMessage(store.MessageRecord{
		QueueID:      id.String(),
		Client:       msg.Client,
		Route:        msg.Route,
		EnvelopeFrom: msg.EnvelopeFrom,
		Recipients:   string(recipientsJSON),
		Subject:      msg.Subject,
		Listener:     msg.Listener,
		RemoteAddr:   "internal",
		ContentType:  ContentType,
		SizeBytes:    int64(len(data)),
		HeaderCount:  rewrite.HeaderCount(headerBlock(data)),
		ReceivedAt:   now,
		ExpiresAt:    now.Add(lifetime),
	}); rerr != nil {
		log.Warn("recording a relay-composed message in history failed",
			"queue_id", id.String(), "listener", msg.Listener, "error", rerr)
	}
	return id, nil
}

// headerBlock returns the header part of a composed message, terminating
// blank line included. A message with no blank line at all is all headers.
func headerBlock(data string) string {
	if i := strings.Index(data, "\r\n\r\n"); i >= 0 {
		return data[:i+4]
	}
	return data
}
