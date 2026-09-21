//go:build loadtest

// Load and capacity measurements. Excluded from the ordinary test run by the
// build tag: they create up to a million messages and take minutes, which is
// a measurement, not a regression check. Run them on purpose with
//
//	go test -tags loadtest -run 'TestLoad' -v ./internal/...

package store

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

// dbMB reports the size of the database plus its WAL sidecar.
func dbMB(dir string) float64 {
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(filepath.Join(dir, "spool", "history.db"+suffix)); err == nil {
			total += fi.Size()
		}
	}
	return float64(total) / (1 << 20)
}

// TestLoadRecordThroughput measures the write path the listener and the
// delivery manager actually use, one call at a time, as they do.
func TestLoadRecordThroughput(t *testing.T) {
	s, dir := loadStore(t)
	defer s.Close()

	const n = 50_000
	now := time.Now().UTC()
	start := time.Now()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("QT%024d", i)
		if err := s.RecordMessage(MessageRecord{
			QueueID: id, Client: "printers", Route: "m365",
			EnvelopeFrom: "device@example.at", Recipients: `["someone@partner.example"]`,
			Subject: "Scan job 4711", Listener: "smtp", RemoteAddr: "10.10.5.42",
			ReceivedAt: now, ExpiresAt: now.Add(96 * time.Hour), SizeBytes: 48000,
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordAttempt(id, 1, 250, "2.0.0 OK", "delivered", nil); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	t.Logf("RecordMessage+RecordAttempt: %d pairs in %v = %.0f messages/s, db %.1f MB",
		n, elapsed.Round(time.Millisecond), float64(n)/elapsed.Seconds(), dbMB(dir))
}

// fill inserts n journal rows in bulk. It bypasses RecordMessage on purpose:
// the point here is how the queries behave against a large table, and the
// per-call write rate is measured separately above.
func fill(t *testing.T, s *Store, n int) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tx.Prepare(`INSERT INTO messages (queue_id, client, route, envelope_from, original_from,
		recipients, subject, listener, remote_addr, received_at, expires_at, tls_used, created_at,
		message_id, content_type, size_bytes, header_count, helo)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	att, err := tx.Prepare(`INSERT INTO attempts (queue_id, attempt_num, at_time, smtp_code, smtp_response, class, created_at)
		VALUES (?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-48 * time.Hour)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("QL%024d", i)
		at := base.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339)
		class := "delivered"
		if i%50 == 0 {
			class = "permanent"
		}
		if _, err := msg.Exec(id, fmt.Sprintf("client-%d", i%20), fmt.Sprintf("route-%d", i%5),
			"device@example.at", "", `["someone@partner.example"]`, "Scan job 4711",
			"smtp", "10.10.5.42", at, base.Add(96*time.Hour).Format(time.RFC3339), 1, at,
			"<abc@example.at>", "application/pdf", 48000, 12, "printer-01"); err != nil {
			t.Fatal(err)
		}
		if _, err := att.Exec(id, 1, at, 250, "2.0.0 OK", class, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// TestLoadQueriesAtOneMillion measures both sides of the journal, in one run,
// on purpose.
//
// The summary columns were added on the strength of the read numbers alone
// and the write path was not measured until the next review: it had lost 61%,
// from 2 829 message+attempt pairs a second to 1 096. A read-only measurement
// makes a denormalisation look free, because on the read side it is. Anything
// that changes the schema or the indexes has to show both columns of the
// ledger here, in the same run, or the next trade is made blind the same way.
func TestLoadQueriesAtOneMillion(t *testing.T) {
	s, dir := loadStore(t)
	defer s.Close()

	// The write path first, through the calls the listener and the delivery
	// worker actually make, before the table is large enough to change what
	// is being measured.
	const writes = 20_000
	now := time.Now().UTC()
	start := time.Now()
	for i := 0; i < writes; i++ {
		id := fmt.Sprintf("QW%024d", i)
		if err := s.RecordMessage(MessageRecord{
			QueueID: id, Client: "printers", Route: "m365",
			EnvelopeFrom: "device@example.at", Recipients: `["someone@partner.example"]`,
			Subject: "Scan job 4711", Listener: "smtp", RemoteAddr: "10.10.5.42",
			ReceivedAt: now, ExpiresAt: now.Add(96 * time.Hour), SizeBytes: 48000,
		}); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordAttempt(id, 1, 250, "2.0.0 OK", "delivered", nil); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	t.Logf("  %-42s %.0f pairs/s", "WRITE: RecordMessage+RecordAttempt", float64(writes)/elapsed.Seconds())

	start = time.Now()
	fill(t, s, 1_000_000)
	t.Logf("filled 1 000 000 messages + attempts in %v, db %.1f MB",
		time.Since(start).Round(time.Second), dbMB(dir))

	timed := func(name string, fn func() error) {
		start := time.Now()
		if err := fn(); err != nil {
			t.Errorf("%s: %v", name, err)
			return
		}
		t.Logf("  %-42s %v", name, time.Since(start).Round(time.Millisecond))
	}

	timed("FindMessages, first queue page", func() error {
		_, _, err := s.FindMessages(MessageFilter{Status: "active", Limit: 50})
		return err
	})
	timed("FindMessages, deep page (offset 100000)", func() error {
		_, _, err := s.FindMessages(MessageFilter{Limit: 50, Offset: 100_000})
		return err
	})
	timed("FindMessages, sender substring filter", func() error {
		_, _, err := s.FindMessages(MessageFilter{Sender: "device@", Limit: 50})
		return err
	})
	timed("FindMessages, subject substring filter", func() error {
		_, _, err := s.FindMessages(MessageFilter{Subject: "4711", Limit: 50})
		return err
	})
	timed("FindBounces, first page", func() error {
		_, _, err := s.FindBounces(BounceFilter{Limit: 50})
		return err
	})
	timed("FindBounceSummaries, first page", func() error {
		_, _, err := s.FindBounceSummaries(BounceFilter{Limit: 50})
		return err
	})
	timed("FindMessageByID", func() error {
		_, err := s.FindMessageByID("QL" + fmt.Sprintf("%024d", 999_999))
		return err
	})
	// The cutoff has to be past the rows' own age or this measures a no-op:
	// retention is 90 days and the rows are two days old, so "now" for this
	// call is a year out. The delete is what a delivery worker pays for --
	// retentionCleanup is called from inside RecordAttempt.
	var before int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	s.retentionCleanup(time.Now().Add(365 * 24 * time.Hour))
	elapsed = time.Since(start)
	var afterMsgs, afterAttempts int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&afterMsgs); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM attempts`).Scan(&afterAttempts); err != nil {
		t.Fatal(err)
	}
	t.Logf("  %-42s %v  (%d -> %d messages, %d attempts left, db %.1f MB)",
		"retentionCleanup", elapsed.Round(time.Millisecond), before, afterMsgs, afterAttempts, dbMB(dir))
}
