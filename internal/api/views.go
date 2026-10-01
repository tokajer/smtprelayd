// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package api

import (
	"time"

	"github.com/tokajer/smtprelayd/internal/queueid"
	"github.com/tokajer/smtprelayd/internal/store"
)

// The wire contract for /api/v1/messages, /api/v1/messages/{id} and
// /api/v1/bounces lives here rather than on the store types themselves: the
// JSON key names, field order and omitempty behaviour are what
// docs/guides/API.md promises callers, and store.Message, store.Attempt and
// store.BounceSummary are free to change shape for the store's own reasons
// without that being an API change.

// messageView is the JSON shape of one message, as returned by
// GET /messages and GET /messages/{id}.
type messageView struct {
	QueueID      queueid.ID `json:"queue_id"`
	Client       string     `json:"client"`
	Route        string     `json:"route"`
	EnvelopeFrom string     `json:"envelope_from"`
	OriginalFrom string     `json:"original_from,omitempty"`
	Recipients   []string   `json:"recipients"`
	Subject      string     `json:"subject,omitempty"`
	Listener     string     `json:"listener"`
	RemoteAddr   string     `json:"remote_addr"`
	ReceivedAt   time.Time  `json:"received_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	TLSUsed      bool       `json:"tls_used"`
	CreatedAt    time.Time  `json:"created_at"`

	MessageID   string `json:"message_id,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	HeaderCount int    `json:"header_count,omitempty"`
	Helo        string `json:"helo,omitempty"`

	Status   string        `json:"status,omitempty"`
	Attempts []attemptView `json:"attempts,omitempty"`

	AttemptCount int    `json:"attempt_count,omitempty"`
	LastCode     int    `json:"last_smtp_code,omitempty"`
	LastErr      string `json:"last_error,omitempty"`
}

// attemptView is the JSON shape of one delivery attempt, nested under a
// messageView.
type attemptView struct {
	AttemptNum int         `json:"attempt_num"`
	AtTime     time.Time   `json:"at_time"`
	SMTPCode   int         `json:"smtp_code,omitempty"`
	SMTPResp   string      `json:"smtp_response,omitempty"`
	Class      store.Class `json:"class"`
	NextAt     *time.Time  `json:"next_attempt_at,omitempty"`
}

// bounceView is the JSON shape of one row returned by GET /bounces.
type bounceView struct {
	QueueID      queueid.ID `json:"queue_id"`
	Class        string     `json:"class"`
	Client       string     `json:"client"`
	Route        string     `json:"route"`
	EnvelopeFrom string     `json:"envelope_from"`
	OriginalFrom string     `json:"original_from,omitempty"`
	Recipients   []string   `json:"recipients"`
	Subject      string     `json:"subject,omitempty"`
	Attempts     int        `json:"attempts"`
	FirstAttempt time.Time  `json:"first_attempt"`
	LastAttempt  time.Time  `json:"last_attempt"`
	SMTPCode     int        `json:"smtp_code,omitempty"`
	SMTPResponse string     `json:"smtp_response,omitempty"`
}

// newMessageView converts one store.Message into its wire shape.
func newMessageView(m *store.Message) messageView {
	v := messageView{
		QueueID: m.QueueID, Client: m.Client, Route: m.Route,
		EnvelopeFrom: m.EnvelopeFrom, OriginalFrom: m.OriginalFrom,
		Recipients: m.Recipients, Subject: m.Subject,
		Listener: m.Listener, RemoteAddr: m.RemoteAddr,
		ReceivedAt: m.ReceivedAt, ExpiresAt: m.ExpiresAt,
		TLSUsed: m.TLSUsed, CreatedAt: m.CreatedAt,
		MessageID: m.MessageID, ContentType: m.ContentType,
		SizeBytes: m.SizeBytes, HeaderCount: m.HeaderCount, Helo: m.Helo,
		Status:       m.Status,
		AttemptCount: m.AttemptCount, LastCode: m.LastCode, LastErr: m.LastErr,
	}
	if len(m.Attempts) > 0 {
		v.Attempts = make([]attemptView, len(m.Attempts))
		for i, a := range m.Attempts {
			v.Attempts[i] = newAttemptView(a)
		}
	}
	return v
}

// newAttemptView converts one store.Attempt into its wire shape.
func newAttemptView(a store.Attempt) attemptView {
	return attemptView{
		AttemptNum: a.AttemptNum, AtTime: a.AtTime,
		SMTPCode: a.SMTPCode, SMTPResp: a.SMTPResp,
		Class: a.Class, NextAt: a.NextAt,
	}
}

// newBounceView converts one store.BounceSummary into its wire shape.
func newBounceView(b store.BounceSummary) bounceView {
	return bounceView{
		QueueID: b.QueueID, Class: b.Class, Client: b.Client, Route: b.Route,
		EnvelopeFrom: b.EnvelopeFrom, OriginalFrom: b.OriginalFrom,
		Recipients: b.Recipients, Subject: b.Subject,
		Attempts: b.Attempts, FirstAttempt: b.FirstAttempt, LastAttempt: b.LastAttempt,
		SMTPCode: b.SMTPCode, SMTPResponse: b.SMTPResponse,
	}
}
