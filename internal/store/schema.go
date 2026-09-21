// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package store

import (
	"database/sql"
	"fmt"
	"time"
)

// The history database's shape: the tables and indexes it is created with,
// the columns added to schemas written by earlier versions, and the one-off
// backfill each of those needs. It is separated from the write path in
// store.go for the reason query.go is separated from both -- this is the file
// a schema change touches, and none of it runs after startup.

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
			helo TEXT,
			attempt_count INTEGER NOT NULL DEFAULT 0,
			first_attempt_at TEXT,
			last_attempt_at TEXT,
			last_class TEXT,
			last_smtp_code INTEGER,
			last_smtp_response TEXT,
			has_bounced INTEGER NOT NULL DEFAULT 0
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
		// Retention deletes by created_at, now in chunks: without this each
		// chunk would re-scan the whole table to find the next 5 000.
		`CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at)`,
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

	if err := s.migrate(); err != nil {
		return err
	}
	return s.createSummaryIndexes()
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

// summaryColumns carry, on the message row itself, what the list queries used
// to derive by grouping the entire attempts table on every page load: the
// latest attempt, how many there were, when the first and last happened, and
// whether any of them failed permanently. Measured before they existed: 2.98s
// for the first queue page and 11.7s for a deep one at a million messages,
// and the first of those was paid even though that queue was empty -- the
// page was charged for the whole history, not for what it showed.
//
// has_bounced is a column rather than a test on last_class because the two
// are not the same question: a message that failed permanently and was then
// requeued and delivered belongs in the bounce view, and its latest attempt
// says "delivered".
var summaryColumns = []struct{ name, decl string }{
	{"attempt_count", "attempt_count INTEGER NOT NULL DEFAULT 0"},
	{"first_attempt_at", "first_attempt_at TEXT"},
	{"last_attempt_at", "last_attempt_at TEXT"},
	{"last_class", "last_class TEXT"},
	{"last_smtp_code", "last_smtp_code INTEGER"},
	{"last_smtp_response", "last_smtp_response TEXT"},
	{"has_bounced", "has_bounced INTEGER NOT NULL DEFAULT 0"},
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

	backfill := false
	for _, c := range summaryColumns {
		if present[c.name] {
			continue
		}
		if _, err := s.db.Exec(`ALTER TABLE messages ADD COLUMN ` + c.decl); err != nil {
			return fmt.Errorf("store: add column %s: %w", c.name, err)
		}
		s.log.Info("store: schema migrated", "added_column", c.name)
		backfill = true
	}
	if backfill {
		if err := s.backfillSummaries(); err != nil {
			return err
		}
	}

	return nil
}

// backfillSummaries fills the summary columns for rows written before they
// existed. It runs once, immediately after the columns are added, because a
// row left at the DEFAULT would read as "never attempted" -- which for an
// old bounce is not merely stale but wrong.
//
// One statement per column rather than one correlated pass: SQLite has no
// UPDATE ... FROM in every build this driver may be compiled from, and each
// of these is a single scan against idx_attempts_queue_time.
func (s *Store) backfillSummaries() error {
	start := time.Now()
	stmts := []string{
		`UPDATE messages SET attempt_count =
			(SELECT COUNT(*) FROM attempts a WHERE a.queue_id = messages.queue_id)`,
		`UPDATE messages SET first_attempt_at =
			(SELECT MIN(a.at_time) FROM attempts a WHERE a.queue_id = messages.queue_id)`,
		`UPDATE messages SET last_attempt_at =
			(SELECT MAX(a.at_time) FROM attempts a WHERE a.queue_id = messages.queue_id)`,
		// Latest by id, not by at_time: at_time has second precision, so two
		// attempts in the same second would otherwise be indistinguishable.
		`UPDATE messages SET last_class =
			(SELECT a.class FROM attempts a WHERE a.queue_id = messages.queue_id ORDER BY a.id DESC LIMIT 1)`,
		`UPDATE messages SET last_smtp_code =
			(SELECT a.smtp_code FROM attempts a WHERE a.queue_id = messages.queue_id ORDER BY a.id DESC LIMIT 1)`,
		`UPDATE messages SET last_smtp_response =
			(SELECT a.smtp_response FROM attempts a WHERE a.queue_id = messages.queue_id ORDER BY a.id DESC LIMIT 1)`,
		`UPDATE messages SET has_bounced = 1 WHERE EXISTS
			(SELECT 1 FROM attempts a WHERE a.queue_id = messages.queue_id AND a.class IN ('permanent', 'expired'))`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("store: backfill attempt summaries: %w", err)
		}
	}
	s.log.Info("store: attempt summaries backfilled", "took", time.Since(start).String())
	return nil
}

// summaryIndexes are created after migrate rather than in createSchema: on a
// database written before the summary columns existed, CREATE TABLE IF NOT
// EXISTS leaves the old column set in place, so an index naming one of them
// fails until the ALTER TABLE above has run.
//
// Both are chosen against the query planner, not against intuition. The
// bounce view is "every message that ever failed permanently", newest first,
// and EXPLAIN QUERY PLAN shows idx_messages_bounced serving both the filter
// and the ordering. The queue view filters on the latest attempt's class,
// where the planner uses idx_messages_lastclass for a MULTI-INDEX OR and
// still sorts in a temp b-tree afterwards -- the index earns its keep on the
// filter, not on the order.
//
// Each of these costs write throughput: measured, the summary columns and
// their indexes together took the journal from 2 829 message+attempt pairs a
// second to 1 096. That is still above the spool's own 744, so the journal is
// not the relay's ceiling -- but the margin is not large enough to add an
// index without checking the planner first.
var summaryIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_messages_bounced ON messages(has_bounced, received_at)`,
	`CREATE INDEX IF NOT EXISTS idx_messages_lastclass ON messages(last_class, received_at)`,
}

// droppedIndexes are indexes earlier versions created that turned out to earn
// nothing. Without dropping them a database that already has one keeps paying
// for it on every write, forever.
//
// idx_messages_lastattempt was added for FindBounceSummaries' ORDER BY
// last_attempt_at. The planner never chose it: it takes idx_messages_bounced
// for the has_bounced filter and sorts in a temp b-tree, so the index was
// pure write cost on a path that had just lost 61% of its throughput.
var droppedIndexes = []string{
	`DROP INDEX IF EXISTS idx_messages_lastattempt`,
}

func (s *Store) createSummaryIndexes() error {
	for _, q := range summaryIndexes {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("store: create summary index: %w", err)
		}
	}
	for _, q := range droppedIndexes {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("store: drop unused index: %w", err)
		}
	}
	return nil
}
