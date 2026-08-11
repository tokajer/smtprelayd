// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store persists message and delivery attempt history.
type Store struct {
	db           *sql.DB
	log          *slog.Logger
	retentionTTL time.Duration
	retain       retentionConfig
	mu           sync.Mutex
	lastCleanup  time.Time
}

type retentionConfig struct {
	days           int
	retainSubjects bool
}

// Open creates or opens the history database at the given path.
func Open(dataDir string, log *slog.Logger, retentionDays int, retainSubjects bool) (*Store, error) {
	spoolDir := filepath.Join(dataDir, "spool")
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create spool dir: %w", err)
	}

	dbPath := filepath.Join(spoolDir, "history.db")
	connStr := "file:" + dbPath + "?cache=shared&mode=rwc&_journal_mode=WAL&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", connStr)
	if err != nil {
		return nil, fmt.Errorf("store: open database: %w", err)
	}

	// Ensure connection is alive.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping database: %w", err)
	}

	s := &Store{
		db:           db,
		log:          log,
		retentionTTL: time.Duration(retentionDays) * 24 * time.Hour,
		retain: retentionConfig{
			days:           retentionDays,
			retainSubjects: retainSubjects,
		},
		lastCleanup: time.Now(),
	}

	if err := s.createSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return s, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// createSchema creates tables if they do not exist.
func (s *Store) createSchema() error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS messages (
			queue_id TEXT PRIMARY KEY,
			client TEXT NOT NULL,
			route TEXT NOT NULL,
			envelope_from TEXT NOT NULL,
			original_from TEXT,
			recipients TEXT NOT NULL,
			subject TEXT,
			listener TEXT NOT NULL,
			remote_addr TEXT NOT NULL,
			received_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			tls_used INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			message_id TEXT,
			content_type TEXT,
			size_bytes INTEGER,
			header_count INTEGER,
			helo TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			queue_id TEXT NOT NULL,
			attempt_num INTEGER NOT NULL,
			at_time TEXT NOT NULL,
			smtp_code INTEGER,
			smtp_response TEXT,
			class TEXT NOT NULL,
			next_attempt_at TEXT,
			created_at TEXT NOT NULL,
			FOREIGN KEY (queue_id) REFERENCES messages(queue_id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS audit (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			at_time TEXT NOT NULL,
			token_name TEXT NOT NULL,
			source_addr TEXT NOT NULL,
			action TEXT NOT NULL,
			queue_id TEXT,
			details TEXT,
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_messages_route_received ON messages(route, received_at)`,
		`CREATE INDEX IF NOT EXISTS idx_messages_client_received ON messages(client, received_at)`,
		`CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_attempts_queue_time ON attempts(queue_id, at_time)`,
		`CREATE INDEX IF NOT EXISTS idx_attempts_time ON attempts(at_time)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_time ON audit(at_time)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_queue ON audit(queue_id)`,
	}

	for _, sql := range tables {
		if _, err := s.db.Exec(sql); err != nil {
			return fmt.Errorf("store: create schema: %w", err)
		}
	}

	return s.migrate()
}

// journalColumns are the per-message metadata columns added after the first
// released schema. `CREATE TABLE IF NOT EXISTS` never touches a table that
// already exists, so a database written by an earlier version keeps the old
// column set until it is migrated here.
var journalColumns = []struct{ name, decl string }{
	{"message_id", "message_id TEXT"},
	{"content_type", "content_type TEXT"},
	{"size_bytes", "size_bytes INTEGER"},
	{"header_count", "header_count INTEGER"},
	{"helo", "helo TEXT"},
}

// migrate adds columns missing from an existing database. Every added column
// is nullable with no default, so rows written before the migration read back
// as NULL — an unknown value, which is what they are — rather than as a
// fabricated zero.
func (s *Store) migrate() error {
	rows, err := s.db.Query(`PRAGMA table_info(messages)`)
	if err != nil {
		return fmt.Errorf("store: inspect messages table: %w", err)
	}
	present := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("store: scan table info: %w", err)
		}
		present[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("store: table info query error: %w", err)
	}
	rows.Close()

	for _, c := range journalColumns {
		if present[c.name] {
			continue
		}
		// The column name is a package constant, never request input.
		if _, err := s.db.Exec(`ALTER TABLE messages ADD COLUMN ` + c.decl); err != nil {
			return fmt.Errorf("store: add column %s: %w", c.name, err)
		}
		s.log.Info("store: schema migrated", "added_column", c.name)
	}

	return nil
}

// MessageRecord is one accepted message as it enters the history journal.
// It is a struct rather than a parameter list because the record is eleven
// strings wide: two adjacent ones transposed at a call site would still
// compile and would silently store a sender as a recipient list.
type MessageRecord struct {
	QueueID      string
	Client       string
	Route        string
	EnvelopeFrom string
	OriginalFrom string
	Recipients   string // JSON array
	Subject      string
	Listener     string
	RemoteAddr   string

	// Journal metadata about the message itself, all taken from what was
	// actually spooled rather than from what the client announced.
	MessageID   string // Message-ID header, "" when absent
	ContentType string // Content-Type header, "" when absent
	SizeBytes   int64  // octets spooled, excluding the relay's own Received header
	HeaderCount int    // header fields after rewriting
	Helo        string // HELO/EHLO name the client announced, "" for relay-generated mail

	ReceivedAt time.Time
	ExpiresAt  time.Time
	TLSUsed    bool
}

// RecordMessage inserts a message record.
// Subject is redacted to empty string if retain_subjects is false.
func (s *Store) RecordMessage(rec MessageRecord) error {
	subject := rec.Subject
	if !s.retain.retainSubjects {
		subject = ""
	}

	tlsInt := 0
	if rec.TLSUsed {
		tlsInt = 1
	}

	now := time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO messages (queue_id, client, route, envelope_from, original_from, recipients, subject, listener, remote_addr, received_at, expires_at, tls_used, created_at, message_id, content_type, size_bytes, header_count, helo)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		rec.QueueID, rec.Client, rec.Route, rec.EnvelopeFrom, rec.OriginalFrom, rec.Recipients, subject, rec.Listener, rec.RemoteAddr,
		rec.ReceivedAt.UTC().Format(time.RFC3339), rec.ExpiresAt.UTC().Format(time.RFC3339), tlsInt, now.Format(time.RFC3339),
		rec.MessageID, rec.ContentType, rec.SizeBytes, rec.HeaderCount, rec.Helo,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Duplicate queue ID — message was already recorded.
			return nil
		}
		return fmt.Errorf("store: record message: %w", err)
	}

	return nil
}

// RecordAttempt inserts a delivery attempt record.
// class is one of "delivered", "temporary", "permanent", "expired".
func (s *Store) RecordAttempt(queueID string, attemptNum int, smtpCode int, smtpResponse, class string, nextAttemptAt *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var nextStr *string
	if nextAttemptAt != nil {
		t := nextAttemptAt.UTC().Format(time.RFC3339)
		nextStr = &t
	}

	_, err := s.db.Exec(`
		INSERT INTO attempts (queue_id, attempt_num, at_time, smtp_code, smtp_response, class, next_attempt_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		queueID, attemptNum, now.Format(time.RFC3339), sql.NullInt64{Int64: int64(smtpCode), Valid: smtpCode > 0}, smtpResponse,
		class, nextStr, now.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("store: record attempt: %w", err)
	}

	// Retention cleanup — run periodically, not on every attempt.
	if now.Sub(s.lastCleanup) > 1*time.Hour {
		s.lastCleanup = now
		_ = s.retentionCleanup(now)
	}

	return nil
}

// RecordAudit inserts an audit log entry.
func (s *Store) RecordAudit(tokenName, sourceAddr, action, queueID, details string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO audit (at_time, token_name, source_addr, action, queue_id, details, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`,
		now.Format(time.RFC3339), tokenName, sourceAddr, action, queueID, details, now.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("store: record audit: %w", err)
	}
	return nil
}

// FindAuditByQueueID returns audit entries for one queue ID, most recent
// first. Not otherwise exposed via the API in this phase ("available for
// future audit dashboard" per docs/PHASE4-PLAN.md); used directly by tests
// to confirm an admin action was actually recorded.
func (s *Store) FindAuditByQueueID(queueID string) ([]AuditEntry, error) {
	rows, err := s.db.Query(`
		SELECT at_time, token_name, source_addr, action, details
		FROM audit WHERE queue_id = ? ORDER BY at_time DESC, id DESC
	`, queueID)
	if err != nil {
		return nil, fmt.Errorf("store: find audit: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var atStr string
		if err := rows.Scan(&atStr, &e.TokenName, &e.SourceAddr, &e.Action, &e.Details); err != nil {
			return nil, fmt.Errorf("store: scan audit: %w", err)
		}
		e.AtTime, _ = time.Parse(time.RFC3339, atStr)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: audit query error: %w", err)
	}
	return out, nil
}

// AuditEntry is one recorded admin action.
type AuditEntry struct {
	AtTime     time.Time
	TokenName  string
	SourceAddr string
	Action     string
	Details    string
}

// retentionCleanup deletes messages and cascaded attempts/audit older than retention TTL.
func (s *Store) retentionCleanup(now time.Time) error {
	cutoff := now.Add(-s.retentionTTL).UTC().Format(time.RFC3339)
	result, err := s.db.Exec(`DELETE FROM messages WHERE created_at < ?`, cutoff)
	if err != nil {
		s.log.Warn("store: retention cleanup failed", "error", err)
		return nil // Log but don't fail the service.
	}

	affected, err := result.RowsAffected()
	if err == nil && affected > 0 {
		s.log.Info("store: retention cleanup", "deleted_rows", affected, "cutoff", cutoff)
	}
	return nil
}
