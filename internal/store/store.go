// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tokajer/smtprelayd/internal/fsmode"

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

	// now is where every timestamp this package writes comes from.
	// RetentionSweep and ReconcileRemoved already take or derive their
	// instant from the caller, while the three record methods reached for
	// the wall clock themselves -- which is why two attempts cannot be
	// placed in a known order by a test, and why backfillSummaries has to
	// order on the row id rather than on at_time. Defaults to time.Now; only
	// a test replaces it.
	now func() time.Time
}

// setClock replaces the source of the timestamps this package writes. It
// exists for tests that need two rows at known, distinct instants; nothing in
// the service calls it.
func (s *Store) setClock(f func() time.Time) { s.now = f }

// retentionConfig is the history policy as configured. The retention period
// itself lives in Store.retentionTTL, already converted to a duration; this
// carries what is read back on the way out.
type retentionConfig struct {
	retainSubjects bool
}

// Open creates or opens the history database at the given path.
func Open(dataDir string, log *slog.Logger, retentionDays int, retainSubjects bool) (*Store, error) {
	spoolDir := filepath.Join(dataDir, "spool")
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create spool dir: %w", err)
	}

	dbPath := filepath.Join(spoolDir, "history.db")
	// openPingTimeout is a wall-clock deadline on the very first use of the
	// database, which is where the driver creates the file, replays a `-wal`
	// sidecar left by an unclean stop, and takes its first lock. Five seconds
	// was not enough: a Windows test run whose packages were each roughly six
	// times slower than usual failed here rather than anywhere in the code
	// under test. The relay ships onto exactly that profile -- a Windows VM on
	// shared storage with an on-access scanner -- and the consequence there is
	// a service that will not start, reporting "context deadline exceeded"
	// rather than anything about a slow disk. A generous ceiling costs nothing
	// on a healthy system, where this completes in milliseconds.
	const openPingTimeout = 30 * time.Second
	// WAL, decided 2026-08-12. Until then the DSN carried
	// `_journal_mode=WAL`, which modernc's driver ignores — it reads only
	// `_pragma=` — so the database had always run in the default
	// rollback-journal mode while appearing to be configured otherwise.
	//
	// WAL rather than the rollback journal because readers do not block the
	// writer under it, and reading while writing is this database's normal
	// state: the dashboard and the API query it while the listener and the
	// delivery manager record into it. The cost is that the `-wal` sidecar
	// carries committed transactions the `.db` alone does not, so a backup
	// that copies only the main file loses the most recent rows. That is
	// acceptable here and nowhere else in the tree: the spool is what holds
	// mail the relay took responsibility for, and this database is a metadata
	// journal about it.
	//
	// No `cache=shared`, since 2026-09-18. SQLite discourages shared-cache
	// mode, and under a database/sql pool it replaces the file lock with
	// table locks that surface as SQLITE_LOCKED -- which no busy handler
	// retries -- exactly where WAL's reader/writer independence was the
	// point. A busy_timeout is set instead: with the file lock back in
	// charge, a writer that meets another waits up to five seconds rather
	// than failing at once, and the sixteen-writer test in store_test.go is
	// what checks that this holds.
	//
	// synchronous=NORMAL (1), since 2026-09-19, rather than SQLite's default
	// of FULL. Under FULL every commit fsyncs the WAL, and RecordMessage and
	// RecordAttempt are each their own implicit transaction -- so an accepted
	// message costs two fsyncs here, on top of the three the spool already
	// pays for the message itself. Measured: this journal wrote 10 969
	// message+attempt pairs a second on Linux and 119 on a Windows VM, where
	// the relay's whole sustained throughput was 93 a second. The journal was
	// the ceiling, not the spool.
	//
	// NORMAL is safe for what this file is. In WAL mode it still fsyncs at a
	// checkpoint, so a process crash, a kill -9, or the service being stopped
	// loses nothing; only a power cut or a kernel panic can drop the most
	// recent transactions. What would be lost then is journal rows -- the
	// record *about* mail. The mail is in the spool, which keeps every one of
	// its own fsyncs, and a spooled message whose journal row is missing is
	// still delivered: recover() reads the spool, never this database.
	connStr := "file:" + dbPath + "?mode=rwc" +
		"&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(1)"
	db, err := sql.Open("sqlite", connStr)
	if err != nil {
		return nil, fmt.Errorf("store: open database: %w", err)
	}

	// Ensure connection is alive.
	ctx, cancel := context.WithTimeout(context.Background(), openPingTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping database: %w", err)
	}

	s := &Store{
		db:           db,
		log:          log,
		retentionTTL: time.Duration(retentionDays) * 24 * time.Hour,
		retain:       retentionConfig{retainSubjects: retainSubjects},
		lastCleanup:  time.Now(),
		now:          time.Now,
	}

	// The driver creates the database 0644. It holds every sender, recipient
	// and — with retain_subjects on, the default — every subject, so it is
	// restricted here to match the spool's own 0600. SQLite derives the mode
	// of a journal, WAL or shared-memory sidecar from the main database
	// file, so restricting it before the first write is what keeps those
	// closed too; the explicit pass covers a sidecar an earlier version
	// already left behind at 0644. Only -journal exists today (see the
	// journal-mode note on connStr above), but the mode of a file this
	// database can grow is not a good thing to discover later.
	if err := fsmode.RestrictFile(dbPath); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: restrict database file: %w", err)
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		if err := fsmode.RestrictFile(dbPath + suffix); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store: restrict %s file: %w", suffix, err)
		}
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

	now := s.now().UTC()
	_, err := s.db.Exec(`
		INSERT INTO messages (queue_id, client, route, envelope_from, original_from, recipients, subject, listener, remote_addr, received_at, expires_at, tls_used, created_at, message_id, content_type, size_bytes, header_count, helo)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		rec.QueueID, rec.Client, rec.Route, rec.EnvelopeFrom, rec.OriginalFrom, rec.Recipients, subject, rec.Listener, rec.RemoteAddr,
		rec.ReceivedAt.UTC().Format(time.RFC3339), rec.ExpiresAt.UTC().Format(time.RFC3339), tlsInt, now.Format(time.RFC3339),
		rec.MessageID, rec.ContentType, rec.SizeBytes, rec.HeaderCount, rec.Helo,
	)
	if err != nil {
		// No ErrNoRows branch here: an INSERT never returns it, and a
		// duplicate queue ID surfaces as a UNIQUE constraint violation. The
		// branch that claimed to handle "already recorded" therefore never
		// ran, and swallowing a real write failure into a nil return is the
		// wrong direction for a journal to fail in.
		return fmt.Errorf("store: record message: %w", err)
	}

	return nil
}

// RecordAttempt inserts a delivery attempt record.
// class is one of "delivered", "temporary", "permanent", "expired", or
// "removed" (written by RecordRemoval, never by the delivery worker).
func (s *Store) RecordAttempt(queueID string, attemptNum int, smtpCode int, smtpResponse, class string, nextAttemptAt *time.Time) error {
	now := s.now().UTC()
	var nextStr *string
	if nextAttemptAt != nil {
		t := nextAttemptAt.UTC().Format(time.RFC3339)
		nextStr = &t
	}

	at := now.Format(time.RFC3339)
	code := sql.NullInt64{Int64: int64(smtpCode), Valid: smtpCode > 0}

	// The insert and the summary update are one transaction. They describe
	// the same event, and a crash between them would leave the message row
	// claiming an attempt count the attempts table does not support -- which
	// every list query would then report, since they read the summary and no
	// longer count.
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: record attempt: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`
		INSERT INTO attempts (queue_id, attempt_num, at_time, smtp_code, smtp_response, class, next_attempt_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, queueID, attemptNum, at, code, smtpResponse, class, nextStr, at); err != nil {
		return fmt.Errorf("store: record attempt: %w", err)
	}

	// has_bounced only ever goes up: a message that failed permanently and
	// was then requeued and delivered still belongs in the bounce view, so
	// the flag records that it happened, not what is true now.
	bounced := 0
	if class == "permanent" || class == "expired" {
		bounced = 1
	}
	if _, err := tx.Exec(`
		UPDATE messages SET
			attempt_count = attempt_count + 1,
			first_attempt_at = COALESCE(first_attempt_at, ?),
			last_attempt_at = ?,
			last_class = ?,
			last_smtp_code = ?,
			last_smtp_response = ?,
			has_bounced = MAX(has_bounced, ?)
		WHERE queue_id = ?
	`, at, at, class, code, smtpResponse, bounced, queueID); err != nil {
		return fmt.Errorf("store: record attempt summary: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: record attempt: %w", err)
	}
	return nil
}

// RetentionSweep deletes journal rows past the retention window, at most once
// an hour however often it is called. It returns how many messages went.
//
// It is called from the delivery manager's own tick, next to SweepFailed,
// rather than from RecordAttempt. Measured on a million rows the delete took
// 15.6 seconds, and SQLite has one writer: run from a delivery worker it
// stopped that worker and every other writer with it -- the listener
// journalling incoming mail included -- for as long as it ran. The dispatcher
// is already ticking and owns no message while it does, so the pause costs
// nobody a transaction.
func (s *Store) RetentionSweep(now time.Time) int64 {
	if !s.claimCleanup(now) {
		return 0
	}
	return s.retentionCleanup(now)
}

// claimCleanup reports whether the hourly retention slot is due and takes
// it. The mutex covers this timestamp and nothing else: until 2026-09-18 it
// was held across the INSERT above and, once an hour, across the retention
// DELETE too, so every delivery worker's journal write queued behind one
// mutex and all of them stalled for as long as the DELETE took. sql.DB is
// safe for concurrent use; the only thing that ever needed serialising was
// deciding who runs the cleanup.
func (s *Store) claimCleanup(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.lastCleanup) <= time.Hour {
		return false
	}
	s.lastCleanup = now
	return true
}

// RecordRemoval records that an operator discarded a message from the spool
// before it reached a delivery outcome (the dashboard/API "delete" action).
// Without this, FindMessages' derived status keeps whatever class the last
// real delivery attempt left behind (or none at all), so a discarded message
// would keep matching the "active"/"queued"/"deferred" filters indefinitely
// even though it no longer exists in the spool.
func (s *Store) RecordRemoval(queueID string) error {
	var next int
	row := s.db.QueryRow(`SELECT COALESCE(MAX(attempt_num), 0) + 1 FROM attempts WHERE queue_id = ?`, queueID)
	if err := row.Scan(&next); err != nil {
		return fmt.Errorf("store: record removal: %w", err)
	}
	return s.RecordAttempt(queueID, next, 0, "", "removed", nil)
}

// ReconcileRemoved marks a message removed when its spool copy is already
// gone while its history still says it is queued or deferred.
//
// That combination is reachable without any operator mistake: Spool.recover
// drops metadata without a body and a body without metadata at startup, an
// operator can delete spool files by hand, and a crash between removing the
// files and writing the attempt row leaves the same state. The history row
// then keeps matching the "active" filter the queue view is built on, so the
// message is listed forever and every delete of it answers 404 -- there was
// no way to clear it from the view at all.
//
// It returns false, and writes nothing, for a message that is unknown or has
// already reached an outcome: a delivered or bounced row must not be
// rewritten into a removal just because its spool copy is (correctly) gone.
func (s *Store) ReconcileRemoved(queueID string) (bool, error) {
	msg, err := s.FindMessageByID(queueID)
	if err != nil {
		return false, err
	}
	if msg == nil {
		return false, nil
	}
	switch msg.Status {
	case "queued", "deferred":
		if err := s.RecordRemoval(queueID); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, nil
	}
}

// RecordAudit inserts an audit log entry.
func (s *Store) RecordAudit(tokenName, sourceAddr, action, queueID, details string) error {
	now := s.now().UTC()
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
// future audit dashboard" per docs/dev/PHASE4-PLAN.md); used directly by tests
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

// retentionChunk bounds one DELETE. The whole sweep still removes everything
// past the window, but in transactions short enough that a writer meeting one
// waits inside busy_timeout instead of queueing behind a multi-second lock.
const retentionChunk = 5000

// retentionCleanup deletes messages older than the retention TTL, and with
// them their attempts, which cascade on the foreign key.
//
// Audit rows do not cascade and are never deleted here: the audit table
// carries no foreign key at all, deliberately. What it records is who ran a
// requeue or a delete and from where, and that outlives the message it was
// about -- an audit log that prunes itself along with the evidence is not
// one. The consequence is that the table grows for the life of the service;
// see docs/guides/CONFIGURATION.md section 9, which says so rather than
// leaving an operator to discover it.
//
// The journal is best-effort: a failed cleanup must not take down delivery,
// so it logs and returns rather than propagating the error.
func (s *Store) retentionCleanup(now time.Time) int64 {
	cutoff := now.Add(-s.retentionTTL).UTC().Format(time.RFC3339)
	var total int64
	for {
		// A subselect rather than "DELETE ... LIMIT": the LIMIT form needs
		// SQLITE_ENABLE_UPDATE_DELETE_LIMIT, which is not a guarantee this
		// driver makes. Attempts follow through the ON DELETE CASCADE.
		result, err := s.db.Exec(`DELETE FROM messages WHERE queue_id IN (
			SELECT queue_id FROM messages WHERE created_at < ? LIMIT ?
		)`, cutoff, retentionChunk)
		if err != nil {
			s.log.Warn("store: retention cleanup failed", "error", err, "deleted_so_far", total)
			return total
		}
		affected, err := result.RowsAffected()
		if err != nil || affected == 0 {
			break
		}
		total += affected
		if affected < retentionChunk {
			break
		}
	}
	if total > 0 {
		s.log.Info("store: retention cleanup", "deleted_rows", total, "cutoff", cutoff)
	}
	return total
}
