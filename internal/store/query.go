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

// Redacted is what a subject reads as once history.retain_subjects is off.
//
// There is a second constant of the same spelling in internal/logging, and
// Secret.String in internal/config returns it too. The three are deliberately
// separate: they redact a message subject, a log attribute and a credential,
// and they answer to three different settings. Nothing should merge them --
// but nothing should add a fourth either, which is what the literal in
// internal/bounce had quietly become.
const Redacted = "[redacted]"

// redactSubject applies the retain_subjects policy on the way out.
//
// RecordMessage already writes an empty subject when the setting is off, so
// for rows written since then this changes nothing. It matters for rows
// written while it was still on: flipping the setting has to hide those too,
// and doing it here means neither the dashboard nor the JSON API can forget —
// which is what each of them used to implement separately, in three places.
func (s *Store) redactSubject(subject string) string {
	if s.retain.retainSubjects {
		return subject
	}
	return Redacted
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

// messageColumns is the SELECT list every message query shares, in the order
// messageScan.dest expects it. prefix is the table alias including its dot,
// or "". It exists for the reason journalCols does, one level up: the three
// queries below used to write the list and its scan destinations out
// separately, six places for thirteen columns, and a column added to one
// pair or dropped from another compiles and then scans the wrong value into
// the wrong field.
func messageColumns(prefix string) string {
	return prefix + "queue_id, " + prefix + "client, " + prefix + "route, " +
		prefix + "envelope_from, " + prefix + "original_from, " + prefix + "recipients, " +
		prefix + "subject, " + prefix + "listener, " + prefix + "remote_addr, " +
		prefix + "received_at, " + prefix + "expires_at, " + prefix + "tls_used, " +
		prefix + "created_at, " + journalCols(prefix)
}

// messageScan receives one row of messageColumns and turns it into a
// Message. The timestamps and the recipient list arrive as text and the TLS
// flag as an integer, which is what SQLite stores; message does that
// conversion once for every caller.
type messageScan struct {
	m              Message
	recipientsJSON string
	tlsInt         int
	receivedAt     string
	expiresAt      string
	createdAt      string
	j              journalScan
}

// dest returns the scan destinations for messageColumns, followed by extra,
// which is whatever the caller selected after the shared list.
func (sc *messageScan) dest(extra ...any) []any {
	out := append([]any{
		&sc.m.QueueID, &sc.m.Client, &sc.m.Route, &sc.m.EnvelopeFrom, &sc.m.OriginalFrom,
		&sc.recipientsJSON, &sc.m.Subject, &sc.m.Listener, &sc.m.RemoteAddr,
		&sc.receivedAt, &sc.expiresAt, &sc.tlsInt, &sc.createdAt,
	}, sc.j.dest()...)
	return append(out, extra...)
}

// message finalises the scanned row. A timestamp that does not parse yields
// the zero time rather than an error: the column is written by this package
// in RFC 3339 and a malformed one means the row was edited by hand, which is
// not a reason to fail a whole listing.
func (sc *messageScan) message(s *Store) *Message {
	m := sc.m
	sc.j.apply(&m)
	m.Subject = s.redactSubject(m.Subject)
	m.TLSUsed = sc.tlsInt != 0
	m.ReceivedAt, _ = time.Parse(time.RFC3339, sc.receivedAt)
	m.ExpiresAt, _ = time.Parse(time.RFC3339, sc.expiresAt)
	m.CreatedAt, _ = time.Parse(time.RFC3339, sc.createdAt)
	if err := json.Unmarshal([]byte(sc.recipientsJSON), &m.Recipients); err != nil {
		m.Recipients = []string{}
	}
	return &m
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
	Limit  int    // default 100, capped at MaxPageLimit
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
	"status": `CASE WHEN m.last_class IS NULL THEN 0 WHEN m.last_class = 'temporary' THEN 1 WHEN m.last_class = 'delivered' THEN 2 ELSE 3 END`,
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

// timeColumn is the column a Since/Until window applies to. It is a defined
// type with exactly two values so that the one fragment apply interpolates
// rather than binds can only come from this file, never from a request.
type timeColumn string

const (
	byReceivedAt  timeColumn = "m.received_at"
	byLastAttempt timeColumn = "m.last_attempt_at"
)

// commonFilters is the filtering MessageFilter and BounceFilter have in
// common. The clauses used to be written out once per query builder, three
// times over, and nothing detected a dropped one: deleting a clause from a
// single copy left the whole suite green until TestEveryFilterFieldBinds
// existed. One copy means the clause text -- and, more easily missed, the
// order the values are bound in -- cannot disagree between them.
type commonFilters struct {
	Since, Until *time.Time
	Client       string
	Route        string
	Sender       string
	Recipient    string
	Subject      string
}

func (f MessageFilter) common() commonFilters {
	return commonFilters{
		Since: f.Since, Until: f.Until, Client: f.Client, Route: f.Route,
		Sender: f.Sender, Recipient: f.Recipient, Subject: f.Subject,
	}
}

func (f BounceFilter) common() commonFilters {
	return commonFilters{
		Since: f.Since, Until: f.Until, Client: f.Client, Route: f.Route,
		Sender: f.Sender, Recipient: f.Recipient, Subject: f.Subject,
	}
}

// builder accumulates a query and the values it binds as one thing.
//
// Every list query here is assembled by appending literal fragments and
// appending bound values, and those used to be two statements per clause. A
// fragment added without its value, or a value without its fragment, still
// compiles and still runs -- it shifts every later value onto the wrong
// placeholder, so a filter silently matches on the wrong column rather than
// failing. Pairing them in one call is what makes that unwritable.
//
// Nothing that reaches sql is ever request input: the fragments are literals
// in this file, the column lists are code-side constants, and every value
// goes through args.
type builder struct {
	sql  strings.Builder
	args []any
}

func newBuilder(head string) *builder {
	b := &builder{}
	b.sql.WriteString(head)
	return b
}

// where appends one conjunct and the values its placeholders bind.
func (b *builder) where(clause string, args ...any) {
	b.sql.WriteString(" AND ")
	b.sql.WriteString(clause)
	b.args = append(b.args, args...)
}

// add appends a trailing fragment -- an ORDER BY, a LIMIT -- and its values.
func (b *builder) add(fragment string, args ...any) {
	b.sql.WriteString(fragment)
	b.args = append(b.args, args...)
}

func (b *builder) query() (string, []any) { return b.sql.String(), b.args }

// apply appends the shared clauses and the values they bind. The queue and
// bounce views window on when a message arrived; the bounce summary windows
// on when it last failed, which is why the column is a parameter.
func (f commonFilters) apply(b *builder, col timeColumn) {
	if f.Since != nil {
		b.where(string(col)+" >= ?", f.Since.UTC().Format(time.RFC3339))
	}
	if f.Until != nil {
		b.where(string(col)+" <= ?", f.Until.UTC().Format(time.RFC3339))
	}
	if f.Client != "" {
		b.where("m.client = ?", f.Client)
	}
	if f.Route != "" {
		b.where("m.route = ?", f.Route)
	}
	if f.Sender != "" {
		b.where("m.envelope_from LIKE ?", "%"+f.Sender+"%")
	}
	if f.Recipient != "" {
		// Substring match via LIKE; the value is bound as a parameter, never
		// interpolated, so characters meaningful to LIKE (% and _) only ever
		// widen or narrow the match, they cannot change the query structure.
		b.where("m.recipients LIKE ?", "%"+f.Recipient+"%")
	}
	if f.Subject != "" {
		b.where("m.subject LIKE ?", "%"+f.Subject+"%")
	}
}

// FindMessageByID retrieves a single message with all its attempts.
func (s *Store) FindMessageByID(queueID string) (*Message, error) {
	var sc messageScan

	//#nosec G202 -- messageColumns is a package constant column list, not input; the only bound value is queueID
	row := s.db.QueryRow(`
		SELECT `+messageColumns("")+`
		FROM messages
		WHERE queue_id = ?
	`, queueID)

	err := row.Scan(sc.dest()...)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: find message: %w", err)
	}
	m := sc.message(s)

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

	return m, nil
}

// MaxOffset bounds how deep any list query may page. An offset past the end
// of the result set costs SQLite a walk of the whole set before it can return
// nothing, so leaving it unbounded turns one crafted request into a full scan.
// Measured on 20,000 messages: 7.5ms at offset 0 against 31ms past the end.
//
// A million rows is far beyond what history.retention_days accumulates at this
// relay's load, so no legitimate paging reaches it. Out of range resets to the
// start, which is how an invalid cursor already behaves.
//
// It lives here because this is the choke point every list query passes
// through, and it is exported for the reason MaxPageLimit is: internal/api
// clamps its own cursor too, so that the cursor it hands back names the page
// it actually served. That clamp has to be this number, not a copy of it --
// two spellings would go on being enforced separately after one moved.
const MaxOffset = 1_000_000

// MaxPageLimit is the largest page any list query will return, whatever the
// caller asks for. It is exported because internal/web bounds one bulk action
// by it: a caller that asks for more silently gets this many, so a constant
// over there carrying a different number would be a lie rather than a
// setting.
const MaxPageLimit = 1000

// clampPaging applies the shared bounds every list query needs. Returning the
// values rather than mutating a filter keeps it usable for the three filter
// types, which share no interface.
func clampPaging(limit, offset int) (int, int) {
	switch {
	case limit <= 0:
		// Also catches a negative one, which SQLite reads as "no limit":
		// FindBounces tested for == 0 and so passed that straight through.
		limit = 100
	case limit > MaxPageLimit:
		limit = MaxPageLimit
	}
	if offset < 0 || offset > MaxOffset {
		offset = 0
	}
	return limit, offset
}

// splitPage separates the extra row a paged query fetches from the page
// itself. Every query here asks for limit+1 so that "is there another page"
// is answered by the same round trip -- but that row is bookkeeping, and
// returning it left each caller to remember to cut it off. One of them
// getting that wrong shows up as a page with one row too many, which is the
// kind of thing nobody reports.
func splitPage[T any](rows []T, limit int) ([]T, bool) {
	if len(rows) > limit {
		return rows[:limit], true
	}
	return rows, false
}

// FindMessages queries messages with filtering, sorting and pagination.
// Status comes from last_class, which RecordAttempt maintains on the message
// row: no attempt yet is "queued", the latest attempt's class otherwise --
// the same definition deriveStatus applies when it is given the full attempt
// history instead.
func (s *Store) FindMessages(filter MessageFilter) ([]*Message, bool, error) {
	filter.Limit, filter.Offset = clampPaging(filter.Limit, filter.Offset)

	//#nosec G202 -- every fragment appended below is a string literal and every value is bound; messageColumns and messageSortColumns are fixed, code-side lists
	b := newBuilder(`
		SELECT ` + messageColumns("m.") + `, m.last_class, m.last_smtp_code, m.last_smtp_response, m.attempt_count
		FROM messages m
		WHERE 1=1
	`)

	filter.common().apply(b, byReceivedAt)
	switch filter.Status {
	case "":
		// No filter.
	case "queued":
		b.where("m.last_class IS NULL")
	case "active":
		b.where("(m.last_class IS NULL OR m.last_class = 'temporary')")
	default:
		classes, ok := statusClasses[filter.Status]
		if !ok {
			return nil, false, fmt.Errorf("store: unknown status %q", filter.Status)
		}
		placeholders := make([]string, len(classes))
		values := make([]any, len(classes))
		for i, c := range classes {
			placeholders[i], values[i] = "?", c
		}
		b.where("m.last_class IN ("+strings.Join(placeholders, ",")+")", values...)
	}

	col, ok := messageSortColumns[filter.Sort]
	if !ok {
		col = messageSortColumns["received_at"]
	}
	order := "DESC"
	if filter.Order == "asc" {
		order = "ASC"
	}
	// +1 to detect "has more"
	b.add(fmt.Sprintf(" ORDER BY %s %s LIMIT ? OFFSET ?", col, order), filter.Limit+1, filter.Offset)

	query, args := b.query()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, false, fmt.Errorf("store: find messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		var sc messageScan
		var latestClass, latestResp sql.NullString
		var latestCode, attemptCount sql.NullInt64

		if err := rows.Scan(sc.dest(&latestClass, &latestCode, &latestResp, &attemptCount)...); err != nil {
			return nil, false, fmt.Errorf("store: scan message: %w", err)
		}

		m := sc.message(s)
		m.LastCode = int(latestCode.Int64)
		m.LastErr = latestResp.String
		m.AttemptCount = int(attemptCount.Int64)
		m.Status = classToStatus(latestClass.String, latestClass.Valid)

		messages = append(messages, m)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("store: messages query error: %w", err)
	}

	messages, hasMore := splitPage(messages, filter.Limit)
	return messages, hasMore, nil
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
func (s *Store) FindBounces(filter BounceFilter) ([]*Message, bool, error) {
	filter.Limit, filter.Offset = clampPaging(filter.Limit, filter.Offset)

	// Find queue IDs that have a final attempt with class='permanent' or 'expired'.
	//#nosec G202 -- as in FindMessages: literal fragments, bound values, code-side column list
	b := newBuilder(`
		SELECT ` + messageColumns("m.") + `, m.last_smtp_code, m.last_smtp_response, m.attempt_count
		FROM messages m
		WHERE m.has_bounced = 1
	`)

	filter.common().apply(b, byReceivedAt)
	if filter.Class != "" {
		// The filter is on the latest attempt's class, which is what the
		// bounce view displays, and not on has_bounced: the two answer
		// different questions, and a message that failed permanently and was
		// then requeued and delivered is in this list with last_class
		// "delivered". FindBounceSummaries filters the same way.
		b.where("m.last_class = ?", filter.Class)
	}
	b.add(" ORDER BY m.received_at DESC LIMIT ? OFFSET ?", filter.Limit+1, filter.Offset)

	query, args := b.query()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, false, fmt.Errorf("store: find bounces: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		var sc messageScan
		var lastResp sql.NullString
		var lastCode, attemptCount sql.NullInt64

		if err := rows.Scan(sc.dest(&lastCode, &lastResp, &attemptCount)...); err != nil {
			return nil, false, fmt.Errorf("store: scan bounce: %w", err)
		}

		m := sc.message(s)
		m.LastCode = int(lastCode.Int64)
		m.LastErr = lastResp.String
		m.AttemptCount = int(attemptCount.Int64)
		m.Status = "bounced"

		messages = append(messages, m)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("store: bounces query error: %w", err)
	}

	messages, hasMore := splitPage(messages, filter.Limit)
	return messages, hasMore, nil
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
	filter.Limit, filter.Offset = clampPaging(filter.Limit, filter.Offset)

	b := newBuilder(`
		SELECT m.queue_id, m.client, m.route, m.envelope_from, m.original_from, m.recipients, m.subject,
		       m.attempt_count, m.first_attempt_at, m.last_attempt_at,
		       m.last_class, m.last_smtp_code, m.last_smtp_response
		FROM messages m
		WHERE m.has_bounced = 1
	`)
	filter.common().apply(b, byLastAttempt)
	if filter.Class != "" {
		b.where("m.last_class = ?", filter.Class)
	}
	b.add(" ORDER BY m.last_attempt_at DESC LIMIT ? OFFSET ?", filter.Limit+1, filter.Offset)

	query, args := b.query()
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
		b.Subject = s.redactSubject(b.Subject)
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

	out, hasMore := splitPage(out, filter.Limit)
	return out, hasMore, nil
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
