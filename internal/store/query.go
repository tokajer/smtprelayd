// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
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

	// Journal metadata. A row written before these columns existed reads
	// back as the zero value; SizeBytes and HeaderCount are omitted from
	// JSON when zero, which is also what an empty message would report and
	// is the reason neither is a useful filter.
	MessageID   string `json:"message_id,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	HeaderCount int    `json:"header_count,omitempty"`
	Helo        string `json:"helo,omitempty"`

	Status   string    `json:"status,omitempty"`   // queued, deferred, delivered, bounced
	Attempts []Attempt `json:"attempts,omitempty"` // per-message details query

	// Outcome of the most recent attempt, carried on the message itself so
	// that a list view can show why something is deferred or bounced
	// without a per-row query for its attempt history.
	AttemptCount int    `json:"attempt_count,omitempty"`
	LastCode     int    `json:"last_smtp_code,omitempty"`
	LastErr      string `json:"last_error,omitempty"`
}

// journalScan receives the journal columns during a row scan. They are
// nullable because they were added to an existing schema (see migrate), so a
// message recorded by an earlier version has no value for them and must not
// scan into a plain string or int.
type journalScan struct {
	messageID   sql.NullString
	contentType sql.NullString
	sizeBytes   sql.NullInt64
	headerCount sql.NullInt64
	helo        sql.NullString
}

// journalCols is the column list every message query selects, in the order
// journalScan expects them. Kept in one place so a query and its scan cannot
// drift apart; prefix is the table alias including its dot, or "".
func journalCols(prefix string) string {
	return prefix + "message_id, " + prefix + "content_type, " + prefix + "size_bytes, " +
		prefix + "header_count, " + prefix + "helo"
}

func (j *journalScan) dest() []interface{} {
	return []interface{}{&j.messageID, &j.contentType, &j.sizeBytes, &j.headerCount, &j.helo}
}

func (j *journalScan) apply(m *Message) {
	m.MessageID = j.messageID.String
	m.ContentType = j.contentType.String
	m.SizeBytes = j.sizeBytes.Int64
	m.HeaderCount = int(j.headerCount.Int64)
	m.Helo = j.helo.String
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
	Sender    string     // substring match on the envelope sender
	Recipient string     // substring match
	Subject   string     // substring match; matches nothing meaningful once retain_subjects redacts a row
	// Status is one of "", "queued", "deferred", "delivered", "bounced",
	// "removed" (discarded by an operator before reaching an outcome), or
	// "active" (queued or deferred, i.e. still in the spool) for the live
	// queue view; "" means any.
	Status string
	Sort   string // received_at (default), client, route; unknown values fall back to the default
	Order  string // desc (default) or asc; unknown values fall back to the default
	Limit  int    // default 100, max 1000
	Offset int
}

// messageSortColumns allowlists the columns FindMessages may sort by. The
// value from a request is never interpolated into the query directly: it is
// looked up here first, and an unknown key falls back to the default rather
// than being rejected, since sorting is a display preference, not something
// that needs to fail a request over.
var messageSortColumns = map[string]string{
	"received_at": "m.received_at",
	"client":      "m.client",
	"route":       "m.route",
	// Status is derived, not stored, so sorting by it needs a synthesised
	// rank rather than a column: queued, then deferred, then delivered,
	// then bounced/removed sharing the last rank. The mapping is fixed
	// here, never influenced by request input, so this is as safe to
	// interpolate as any other allowlisted column.
	"status": `CASE WHEN latest.class IS NULL THEN 0 WHEN latest.class = 'temporary' THEN 1 WHEN latest.class = 'delivered' THEN 2 ELSE 3 END`,
}

// statusClasses maps a display status onto the attempt classes that produce
// it. "queued" has no rows in attempts at all, which the query below handles
// separately from this list.
var statusClasses = map[string][]string{
	"deferred":  {"temporary"},
	"delivered": {"delivered"},
	"bounced":   {"permanent", "expired"},
	"removed":   {"removed"},
}

// BounceFilter specifies query parameters for FindBounces.
type BounceFilter struct {
	Since     *time.Time
	Until     *time.Time
	Client    string
	Route     string
	Sender    string
	Recipient string
	Subject   string
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
	var j journalScan

	//#nosec G202 -- journalCols is a package constant column list, not input; the only bound value is queueID
	row := s.db.QueryRow(`
		SELECT queue_id, client, route, envelope_from, original_from, recipients, subject, listener, remote_addr, received_at, expires_at, tls_used, created_at,
		       `+journalCols("")+`
		FROM messages
		WHERE queue_id = ?
	`, queueID)

	err := row.Scan(append([]interface{}{
		&m.QueueID, &m.Client, &m.Route, &m.EnvelopeFrom, &m.OriginalFrom, &recipientsJSON, &m.Subject, &m.Listener, &m.RemoteAddr,
		&receivedAtStr, &expiresAtStr, &tlsInt, &createdAtStr,
	}, j.dest()...)...)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: find message: %w", err)
	}

	m.ReceivedAt, _ = time.Parse(time.RFC3339, receivedAtStr)
	m.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAtStr)
	m.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
	j.apply(&m)

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
	m.AttemptCount = len(m.Attempts)
	if len(m.Attempts) > 0 {
		last := m.Attempts[len(m.Attempts)-1]
		m.LastCode, m.LastErr = last.SMTPCode, last.SMTPResp
	}

	return &m, nil
}

// FindMessages queries messages with filtering, sorting and pagination.
// Status is derived from the most recent attempt, the same definition
// CountQueue and deriveStatus use: no attempts is "queued", the latest
// attempt's class otherwise.
func (s *Store) FindMessages(filter MessageFilter) ([]*Message, error) {
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}

	//#nosec G202 -- every fragment appended below is a string literal and every value is bound; journalCols and messageSortColumns are fixed, code-side lists
	query := `
		SELECT m.queue_id, m.client, m.route, m.envelope_from, m.original_from, m.recipients, m.subject, m.listener, m.remote_addr, m.received_at, m.expires_at, m.tls_used, m.created_at,
		       ` + journalCols("m.") + `, latest.class, latest.smtp_code, latest.smtp_response, agg.attempts
		FROM messages m
		LEFT JOIN (
			-- The tiebreak is the autoincrement id, not MAX(at_time): at_time
			-- has only second precision, so two attempts within the same
			-- second would otherwise both match and fan this join out into
			-- duplicate result rows.
			SELECT queue_id, class, smtp_code, smtp_response FROM attempts
			WHERE id IN (
				SELECT MAX(id) FROM attempts GROUP BY queue_id
			)
		) latest ON m.queue_id = latest.queue_id
		LEFT JOIN (
			SELECT queue_id, COUNT(*) AS attempts FROM attempts GROUP BY queue_id
		) agg ON m.queue_id = agg.queue_id
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
	if filter.Sender != "" {
		query += " AND m.envelope_from LIKE ?"
		args = append(args, "%"+filter.Sender+"%")
	}
	if filter.Recipient != "" {
		// Substring match via LIKE; the value is bound as a parameter, never
		// interpolated, so characters meaningful to LIKE (% and _) only ever
		// widen or narrow the match, they cannot change the query structure.
		query += " AND m.recipients LIKE ?"
		args = append(args, "%"+filter.Recipient+"%")
	}
	if filter.Subject != "" {
		query += " AND m.subject LIKE ?"
		args = append(args, "%"+filter.Subject+"%")
	}
	switch filter.Status {
	case "":
		// No filter.
	case "queued":
		query += " AND latest.class IS NULL"
	case "active":
		query += " AND (latest.class IS NULL OR latest.class = 'temporary')"
	default:
		classes, ok := statusClasses[filter.Status]
		if !ok {
			return nil, fmt.Errorf("store: unknown status %q", filter.Status)
		}
		placeholders := make([]string, len(classes))
		for i, c := range classes {
			placeholders[i] = "?"
			args = append(args, c)
		}
		query += " AND latest.class IN (" + strings.Join(placeholders, ",") + ")"
	}

	col, ok := messageSortColumns[filter.Sort]
	if !ok {
		col = messageSortColumns["received_at"]
	}
	order := "DESC"
	if filter.Order == "asc" {
		order = "ASC"
	}
	query += fmt.Sprintf(" ORDER BY %s %s LIMIT ? OFFSET ?", col, order)
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
		var latestClass, latestResp sql.NullString
		var latestCode, attemptCount sql.NullInt64
		var j journalScan

		dest := append([]interface{}{
			&m.QueueID, &m.Client, &m.Route, &m.EnvelopeFrom, &m.OriginalFrom, &recipientsJSON, &m.Subject, &m.Listener, &m.RemoteAddr,
			&receivedAtStr, &expiresAtStr, &tlsInt, &createdAtStr,
		}, j.dest()...)
		dest = append(dest, &latestClass, &latestCode, &latestResp, &attemptCount)
		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("store: scan message: %w", err)
		}

		j.apply(&m)
		m.LastCode = int(latestCode.Int64)
		m.LastErr = latestResp.String
		m.AttemptCount = int(attemptCount.Int64)
		m.TLSUsed = tlsInt != 0
		m.ReceivedAt, _ = time.Parse(time.RFC3339, receivedAtStr)
		m.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAtStr)
		m.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
		if err := json.Unmarshal([]byte(recipientsJSON), &m.Recipients); err != nil {
			m.Recipients = []string{}
		}
		m.Status = classToStatus(latestClass.String, latestClass.Valid)

		messages = append(messages, &m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: messages query error: %w", err)
	}

	return messages, nil
}

// classToStatus applies the same class-to-status mapping deriveStatus uses,
// starting from a nullable "latest attempt class" column instead of a slice
// of attempts.
func classToStatus(class string, hasAttempt bool) string {
	if !hasAttempt {
		return "queued"
	}
	switch class {
	case "delivered":
		return "delivered"
	case "permanent", "expired":
		return "bounced"
	case "removed":
		return "removed"
	default:
		return "deferred"
	}
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
	//#nosec G202 -- as in FindMessages: literal fragments, bound values, code-side column list
	query := `
		SELECT DISTINCT m.queue_id, m.client, m.route, m.envelope_from, m.original_from, m.recipients, m.subject, m.listener, m.remote_addr, m.received_at, m.expires_at, m.tls_used, m.created_at,
		       ` + journalCols("m.") + `, last.smtp_code, last.smtp_response, agg.attempts
		FROM messages m
		INNER JOIN (
			SELECT queue_id FROM attempts WHERE class IN ('permanent', 'expired')
		) a ON m.queue_id = a.queue_id
		INNER JOIN (
			-- Tiebreak on id for the same reason as FindMessages: at_time
			-- alone would duplicate a row whenever two attempts landed in
			-- the same wall-clock second.
			SELECT queue_id, class, smtp_code, smtp_response FROM attempts
			WHERE id IN (SELECT MAX(id) FROM attempts GROUP BY queue_id)
		) last ON m.queue_id = last.queue_id
		INNER JOIN (
			SELECT queue_id, COUNT(*) AS attempts FROM attempts GROUP BY queue_id
		) agg ON m.queue_id = agg.queue_id
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
	if filter.Sender != "" {
		query += " AND m.envelope_from LIKE ?"
		args = append(args, "%"+filter.Sender+"%")
	}
	if filter.Recipient != "" {
		query += " AND m.recipients LIKE ?"
		args = append(args, "%"+filter.Recipient+"%")
	}
	if filter.Subject != "" {
		query += " AND m.subject LIKE ?"
		args = append(args, "%"+filter.Subject+"%")
	}
	if filter.Class != "" {
		// On last.class, not on the a subquery: a selects queue_id alone, so
		// "AND a.class = ?" was a guaranteed SQL error and the dashboard's
		// failure-class filter had never returned anything but a 500. The
		// final attempt's class is also the one the bounce view displays,
		// which is what FindBounceSummaries already filters on.
		query += " AND last.class = ?"
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
		var j journalScan
		var lastResp sql.NullString
		var lastCode, attemptCount sql.NullInt64

		dest := append([]interface{}{
			&m.QueueID, &m.Client, &m.Route, &m.EnvelopeFrom, &m.OriginalFrom, &recipientsJSON, &m.Subject, &m.Listener, &m.RemoteAddr,
			&receivedAtStr, &expiresAtStr, &tlsInt, &createdAtStr,
		}, j.dest()...)
		dest = append(dest, &lastCode, &lastResp, &attemptCount)
		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("store: scan bounce: %w", err)
		}

		j.apply(&m)
		m.LastCode = int(lastCode.Int64)
		m.LastErr = lastResp.String
		m.AttemptCount = int(attemptCount.Int64)
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

// BounceSummary is the flattened view of a bounce the HTTP API returns
// (docs/guides/API.md): the final attempt's class and SMTP response plus a total
// attempt count, rather than the full attempt history FindMessageByID gives.
type BounceSummary struct {
	QueueID      string    `json:"queue_id"`
	Class        string    `json:"class"`
	Client       string    `json:"client"`
	Route        string    `json:"route"`
	EnvelopeFrom string    `json:"envelope_from"`
	OriginalFrom string    `json:"original_from,omitempty"`
	Recipients   []string  `json:"recipients"`
	Subject      string    `json:"subject,omitempty"`
	Attempts     int       `json:"attempts"`
	FirstAttempt time.Time `json:"first_attempt"`
	LastAttempt  time.Time `json:"last_attempt"`
	SMTPCode     int       `json:"smtp_code,omitempty"`
	SMTPResponse string    `json:"smtp_response,omitempty"`
}

// FindBounceSummaries returns the API's flattened bounce view with
// pagination. hasMore reports whether rows exist beyond filter.Limit.
func (s *Store) FindBounceSummaries(filter BounceFilter) ([]BounceSummary, bool, error) {
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}

	query := `
		SELECT m.queue_id, m.client, m.route, m.envelope_from, m.original_from, m.recipients, m.subject,
		       agg.attempts, agg.first_attempt, agg.last_attempt,
		       last.class, last.smtp_code, last.smtp_response
		FROM messages m
		INNER JOIN (
			SELECT queue_id FROM attempts WHERE class IN ('permanent', 'expired')
		) bounced ON m.queue_id = bounced.queue_id
		INNER JOIN (
			SELECT queue_id, COUNT(*) AS attempts, MIN(at_time) AS first_attempt, MAX(at_time) AS last_attempt
			FROM attempts GROUP BY queue_id
		) agg ON m.queue_id = agg.queue_id
		INNER JOIN (
			-- Tiebreak on id, not MAX(at_time): see the comment in
			-- FindMessages on why a same-second collision must not be
			-- allowed to fan this join out into duplicate rows.
			SELECT queue_id, class, smtp_code, smtp_response FROM attempts
			WHERE id IN (SELECT MAX(id) FROM attempts GROUP BY queue_id)
		) last ON m.queue_id = last.queue_id
		WHERE 1=1
	`
	args := []interface{}{}
	if filter.Since != nil {
		query += " AND agg.last_attempt >= ?"
		args = append(args, filter.Since.UTC().Format(time.RFC3339))
	}
	if filter.Until != nil {
		query += " AND agg.last_attempt <= ?"
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
	if filter.Sender != "" {
		query += " AND m.envelope_from LIKE ?"
		args = append(args, "%"+filter.Sender+"%")
	}
	if filter.Recipient != "" {
		query += " AND m.recipients LIKE ?"
		args = append(args, "%"+filter.Recipient+"%")
	}
	if filter.Subject != "" {
		query += " AND m.subject LIKE ?"
		args = append(args, "%"+filter.Subject+"%")
	}
	if filter.Class != "" {
		query += " AND last.class = ?"
		args = append(args, filter.Class)
	}
	query += " ORDER BY agg.last_attempt DESC LIMIT ? OFFSET ?"
	args = append(args, filter.Limit+1, filter.Offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, false, fmt.Errorf("store: find bounce summaries: %w", err)
	}
	defer rows.Close()

	var out []BounceSummary
	for rows.Next() {
		var b BounceSummary
		var recipientsJSON, firstStr, lastStr string
		var smtpCode sql.NullInt64
		var smtpResp sql.NullString
		if err := rows.Scan(&b.QueueID, &b.Client, &b.Route, &b.EnvelopeFrom, &b.OriginalFrom, &recipientsJSON, &b.Subject,
			&b.Attempts, &firstStr, &lastStr, &b.Class, &smtpCode, &smtpResp); err != nil {
			return nil, false, fmt.Errorf("store: scan bounce summary: %w", err)
		}
		if err := json.Unmarshal([]byte(recipientsJSON), &b.Recipients); err != nil {
			b.Recipients = []string{}
		}
		b.FirstAttempt, _ = time.Parse(time.RFC3339, firstStr)
		b.LastAttempt, _ = time.Parse(time.RFC3339, lastStr)
		if smtpCode.Valid {
			b.SMTPCode = int(smtpCode.Int64)
		}
		if smtpResp.Valid {
			b.SMTPResponse = smtpResp.String
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("store: bounce summaries query error: %w", err)
	}

	hasMore := len(out) > filter.Limit
	if hasMore {
		out = out[:filter.Limit]
	}
	return out, hasMore, nil
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
		return classToStatus("", false)
	}
	return classToStatus(attempts[len(attempts)-1].Class, true)
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
			-- Tiebreak on id, not MAX(at_time): see the comment in
			-- FindMessages on why a same-second collision must not be
			-- allowed to fan this join out into duplicate rows.
			SELECT queue_id, class FROM attempts
			WHERE id IN (
				SELECT MAX(id) FROM attempts GROUP BY queue_id
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
