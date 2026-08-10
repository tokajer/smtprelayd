// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Message represents a stored message record.
type Message struct {
	QueueID      string    `json:"queue_id"`
	Client       string    `json:"client"`
	Route        string    `json:"route"`
	EnvelopeFrom string    `json:"envelope_from"`
	OriginalFrom string    `json:"original_from,omitempty"`
	Recipients   []string  `json:"recipients"`
	Subject      string    `json:"subject,omitempty"`
	Listener     string    `json:"listener"`
	RemoteAddr   string    `json:"remote_addr"`
	ReceivedAt   time.Time `json:"received_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	TLSUsed      bool      `json:"tls_used"`
	CreatedAt    time.Time `json:"created_at"`

	Status   string    `json:"status,omitempty"`     // queued, deferred, delivered, bounced
	Attempts []Attempt `json:"attempts,omitempty"`   // per-message details query
	LastErr  string    `json:"last_error,omitempty"` // from last attempt
}

// Attempt represents a single delivery attempt.
type Attempt struct {
	AttemptNum int        `json:"attempt_num"`
	AtTime     time.Time  `json:"at_time"`
	SMTPCode   int        `json:"smtp_code,omitempty"`
	SMTPResp   string     `json:"smtp_response,omitempty"`
	Class      string     `json:"class"`
	NextAt     *time.Time `json:"next_attempt_at,omitempty"`
}

// MessageFilter specifies query parameters for FindMessages.
type MessageFilter struct {
	Since     *time.Time // inclusive
	Until     *time.Time // inclusive
	Client    string     // exact match
	Route     string     // exact match
	Recipient string     // substring match
	Status    string     // queued, deferred, delivered, bounced
	Limit     int        // default 100, max 1000
	Offset    int
}

// BounceFilter specifies query parameters for FindBounces.
type BounceFilter struct {
	Since     *time.Time
	Until     *time.Time
	Client    string
	Route     string
	Recipient string
	Class     string // permanent, expired
	Limit     int
	Offset    int
}

// FindMessageByID retrieves a single message with all its attempts.
func (s *Store) FindMessageByID(queueID string) (*Message, error) {
	var m Message
	var recipientsJSON string
	var tlsInt int
	var receivedAtStr, expiresAtStr, createdAtStr string

	row := s.db.QueryRow(`
		SELECT queue_id, client, route, envelope_from, original_from, recipients, subject, listener, remote_addr, received_at, expires_at, tls_used, created_at
		FROM messages
		WHERE queue_id = ?
	`, queueID)

	err := row.Scan(&m.QueueID, &m.Client, &m.Route, &m.EnvelopeFrom, &m.OriginalFrom, &recipientsJSON, &m.Subject, &m.Listener, &m.RemoteAddr, &receivedAtStr, &expiresAtStr, &tlsInt, &createdAtStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: find message: %w", err)
	}

	m.ReceivedAt, _ = time.Parse(time.RFC3339, receivedAtStr)
	m.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAtStr)
	m.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

	m.TLSUsed = tlsInt != 0
	if err := json.Unmarshal([]byte(recipientsJSON), &m.Recipients); err != nil {
		m.Recipients = []string{}
	}

	// Fetch all attempts for this message.
	rows, err := s.db.Query(`
		SELECT attempt_num, at_time, smtp_code, smtp_response, class, next_attempt_at
		FROM attempts
		WHERE queue_id = ?
		ORDER BY at_time ASC
	`, queueID)
	if err != nil {
		return nil, fmt.Errorf("store: query attempts: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var a Attempt
		var smtpCode sql.NullInt64
		var smtpResp sql.NullString
		var nextAt sql.NullString
		var atTimeStr string

		if err := rows.Scan(&a.AttemptNum, &atTimeStr, &smtpCode, &smtpResp, &a.Class, &nextAt); err != nil {
			return nil, fmt.Errorf("store: scan attempt: %w", err)
		}

		a.AtTime, _ = time.Parse(time.RFC3339, atTimeStr)
		if smtpCode.Valid {
			a.SMTPCode = int(smtpCode.Int64)
		}
		if smtpResp.Valid {
			a.SMTPResp = smtpResp.String
		}
		if nextAt.Valid {
			t, _ := time.Parse(time.RFC3339, nextAt.String)
			a.NextAt = &t
		}

		m.Attempts = append(m.Attempts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: attempts query error: %w", err)
	}

	// Derive status from attempts.
	m.Status = deriveStatus(m.Attempts)
	if len(m.Attempts) > 0 {
		m.LastErr = m.Attempts[len(m.Attempts)-1].SMTPResp
	}

	return &m, nil
}

// FindMessages queries messages with filtering and pagination.
func (s *Store) FindMessages(filter MessageFilter) ([]*Message, error) {
	// Sanitize limit.
	if filter.Limit == 0 {
		filter.Limit = 100
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}

	query := "SELECT queue_id, client, route, envelope_from, original_from, recipients, subject, listener, remote_addr, received_at, expires_at, tls_used, created_at FROM messages WHERE 1=1"
	args := []interface{}{}

	// Build WHERE clause from filters.
	if filter.Since != nil {
		query += " AND received_at >= ?"
		args = append(args, filter.Since.UTC().Format(time.RFC3339))
	}
	if filter.Until != nil {
		query += " AND received_at <= ?"
		args = append(args, filter.Until.UTC().Format(time.RFC3339))
	}
	if filter.Client != "" {
		query += " AND client = ?"
		args = append(args, filter.Client)
	}
	if filter.Route != "" {
		query += " AND route = ?"
		args = append(args, filter.Route)
	}
	if filter.Recipient != "" {
		// Substring match via LIKE.
		query += " AND recipients LIKE ?"
		args = append(args, "%"+filter.Recipient+"%")
	}

	query += " ORDER BY received_at DESC LIMIT ? OFFSET ?"
	args = append(args, filter.Limit+1, filter.Offset) // +1 to detect "has more"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: find messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		var m Message
		var recipientsJSON string
		var tlsInt int
		var receivedAtStr, expiresAtStr, createdAtStr string

		if err := rows.Scan(&m.QueueID, &m.Client, &m.Route, &m.EnvelopeFrom, &m.OriginalFrom, &recipientsJSON, &m.Subject, &m.Listener, &m.RemoteAddr, &receivedAtStr, &expiresAtStr, &tlsInt, &createdAtStr); err != nil {
			return nil, fmt.Errorf("store: scan message: %w", err)
		}

		m.TLSUsed = tlsInt != 0
		m.ReceivedAt, _ = time.Parse(time.RFC3339, receivedAtStr)
		m.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAtStr)
		m.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
		if err := json.Unmarshal([]byte(recipientsJSON), &m.Recipients); err != nil {
			m.Recipients = []string{}
		}

		messages = append(messages, &m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: messages query error: %w", err)
	}

	return messages, nil
}

// FindBounces queries messages that failed (permanent or expired).
func (s *Store) FindBounces(filter BounceFilter) ([]*Message, error) {
	if filter.Limit == 0 {
		filter.Limit = 100
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}

	// Find queue IDs that have a final attempt with class='permanent' or 'expired'.
	query := `
		SELECT DISTINCT m.queue_id, m.client, m.route, m.envelope_from, m.original_from, m.recipients, m.subject, m.listener, m.remote_addr, m.received_at, m.expires_at, m.tls_used, m.created_at
		FROM messages m
		INNER JOIN (
			SELECT queue_id FROM attempts WHERE class IN ('permanent', 'expired')
		) a ON m.queue_id = a.queue_id
		WHERE 1=1
	`
	args := []interface{}{}

	if filter.Since != nil {
		query += " AND m.received_at >= ?"
		args = append(args, filter.Since.UTC().Format(time.RFC3339))
	}
	if filter.Until != nil {
		query += " AND m.received_at <= ?"
		args = append(args, filter.Until.UTC().Format(time.RFC3339))
	}
	if filter.Client != "" {
		query += " AND m.client = ?"
		args = append(args, filter.Client)
	}
	if filter.Route != "" {
		query += " AND m.route = ?"
		args = append(args, filter.Route)
	}
	if filter.Recipient != "" {
		query += " AND m.recipients LIKE ?"
		args = append(args, "%"+filter.Recipient+"%")
	}
	if filter.Class != "" {
		query += " AND a.class = ?"
		args = append(args, filter.Class)
	}

	query += " ORDER BY m.received_at DESC LIMIT ? OFFSET ?"
	args = append(args, filter.Limit+1, filter.Offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: find bounces: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		var m Message
		var recipientsJSON string
		var tlsInt int
		var receivedAtStr, expiresAtStr, createdAtStr string

		if err := rows.Scan(&m.QueueID, &m.Client, &m.Route, &m.EnvelopeFrom, &m.OriginalFrom, &recipientsJSON, &m.Subject, &m.Listener, &m.RemoteAddr, &receivedAtStr, &expiresAtStr, &tlsInt, &createdAtStr); err != nil {
			return nil, fmt.Errorf("store: scan bounce: %w", err)
		}

		m.TLSUsed = tlsInt != 0
		m.ReceivedAt, _ = time.Parse(time.RFC3339, receivedAtStr)
		m.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAtStr)
		m.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
		if err := json.Unmarshal([]byte(recipientsJSON), &m.Recipients); err != nil {
			m.Recipients = []string{}
		}

		m.Status = "bounced"
		messages = append(messages, &m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: bounces query error: %w", err)
	}

	return messages, nil
}

// FindBouncesSince returns bounces after the given time (for notification digest).
func (s *Store) FindBouncesSince(since time.Time) ([]*Message, error) {
	return s.FindBounces(BounceFilter{
		Since: &since,
		Limit: 10000,
	})
}

// deriveStatus infers the message status from its attempts.
// If no attempts: queued.
// If last attempt is "delivered": delivered.
// If last attempt is "permanent" or "expired": bounced.
// Otherwise (temporary): deferred.
func deriveStatus(attempts []Attempt) string {
	if len(attempts) == 0 {
		return "queued"
	}
	last := attempts[len(attempts)-1]
	switch last.Class {
	case "delivered":
		return "delivered"
	case "permanent", "expired":
		return "bounced"
	default:
		return "deferred"
	}
}

// DeleteMessage hard-deletes a message (for admin action).
func (s *Store) DeleteMessage(queueID string) error {
	_, err := s.db.Exec("DELETE FROM messages WHERE queue_id = ?", queueID)
	if err != nil {
		return fmt.Errorf("store: delete message: %w", err)
	}
	return nil
}

// CountByRoute returns queue depth by state and route (for metrics).
type QueueStats struct {
	Route     string
	Queued    int64
	Deferred  int64
	Delivered int64
	Bounced   int64
}

// CountQueue returns queue statistics aggregated by route (for metrics).
func (s *Store) CountQueue() ([]QueueStats, error) {
	// A message is queued if it has no attempts or only temporary attempts.
	// A message is delivered if its last attempt is delivered.
	// A message is bounced if its last attempt is permanent or expired.
	// A message is deferred if its last attempt is temporary.
	// SQLite does not have user-defined functions easily, so we derive the status in Go.

	rows, err := s.db.Query(`
		SELECT m.route, COALESCE(a.class, 'queued') as latest_class
		FROM messages m
		LEFT JOIN (
			SELECT queue_id, class FROM attempts
			WHERE (queue_id, at_time) IN (
				SELECT queue_id, MAX(at_time) FROM attempts GROUP BY queue_id
			)
		) a ON m.queue_id = a.queue_id
	`)
	if err != nil {
		return nil, fmt.Errorf("store: count queue: %w", err)
	}
	defer rows.Close()

	stats := make(map[string]*QueueStats)
	for rows.Next() {
		var route string
		var class string
		if err := rows.Scan(&route, &class); err != nil {
			return nil, fmt.Errorf("store: scan queue stat: %w", err)
		}

		if _, ok := stats[route]; !ok {
			stats[route] = &QueueStats{Route: route}
		}

		st := stats[route]
		switch class {
		case "queued":
			st.Queued++
		case "temporary":
			st.Deferred++
		case "delivered":
			st.Delivered++
		case "permanent", "expired":
			st.Bounced++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: queue count query error: %w", err)
	}

	var result []QueueStats
	for _, s := range stats {
		result = append(result, *s)
	}
	return result, nil
}
