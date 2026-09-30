// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"bufio"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// TestReadDeadlineClampedToSession covers the unmatched-source path: the per
// command deadline is refreshed by every NOOP, so without the clamp a source
// that simply stops sending would outlive its session budget inside one
// blocking read.
func TestReadDeadlineClampedToSession(t *testing.T) {
	s := &session{deadline: time.Now().Add(2 * time.Second)}
	if got := s.readDeadline(60); got.After(s.deadline) {
		t.Fatalf("read deadline %v outlives the session deadline %v", got, s.deadline)
	}
}

func TestReadDeadlineUnclampedWithoutSessionLimit(t *testing.T) {
	// An allowlisted client has no session deadline and must keep the full
	// per command timeout, so a slow device is not disconnected mid-transfer.
	s := &session{}
	got := s.readDeadline(60)
	if got.Before(time.Now().Add(50 * time.Second)) {
		t.Fatalf("read deadline %v was shortened without a session deadline", got)
	}
}

func TestReadDeadlineUsesSessionLimitWhenShorter(t *testing.T) {
	s := &session{deadline: time.Now().Add(time.Hour)}
	// A session budget longer than the command timeout must not extend it.
	if got := s.readDeadline(1); got.After(time.Now().Add(10 * time.Second)) {
		t.Fatalf("session deadline extended the per command timeout to %v", got)
	}
}

func TestSanitizeSubjectStripsControlCharsAndTruncates(t *testing.T) {
	if got := sanitizeSubject("Invoice\x00\x07 due"); got != "Invoice due" {
		t.Errorf("got %q, want control characters stripped", got)
	}
	long := strings.Repeat("a", maxStoredSubject+50)
	if got := sanitizeSubject(long); len(got) != maxStoredSubject {
		t.Errorf("got length %d, want %d", len(got), maxStoredSubject)
	}
}

// A journal value is truncated on a rune boundary: half a rune in the store
// renders as a replacement character on every page that displays it.
func TestSanitizeHeaderMetaTruncatesOnRuneBoundary(t *testing.T) {
	// Ten three-byte runes, cut at 8 bytes: the cut must fall back to 6.
	got := sanitizeHeaderMeta(strings.Repeat("€", 10), 8)
	if len(got) != 6 || !utf8.ValidString(got) {
		t.Errorf("got %q (%d bytes), want a valid 6-byte prefix", got, len(got))
	}
}

// A bare CR inside a command or header line is rejected: the line is
// interpreted or re-emitted, and whether that CR ends a line is then up to
// whichever parser sees it next.
func TestReadStructuredLineRejectsBareCR(t *testing.T) {
	line, err := readStructuredLine(bufio.NewReader(strings.NewReader("Subject: a\rb\r\n")), maxLineOctet)
	if !errors.Is(err, errBareCR) {
		t.Fatalf("got %q, %v; want errBareCR", line, err)
	}

	// The terminator itself is still just a terminator.
	got, err := readStructuredLine(bufio.NewReader(strings.NewReader("Subject: ok\r\n")), maxLineOctet)
	if err != nil || got != "Subject: ok" {
		t.Fatalf("got %q, %v; want the line without its CRLF", got, err)
	}
}

// The body is deliberately exempt: a legacy device emitting a lone CR in a
// plain-text body must not lose the whole message over a byte that cannot
// split a header.
func TestBodyKeepsBareCR(t *testing.T) {
	d := newDotReader(bufio.NewReader(strings.NewReader("line\rone\r\n.\r\n")))
	got, err := io.ReadAll(d)
	if err != nil {
		t.Fatalf("body with a bare CR was rejected: %v", err)
	}
	if string(got) != "line\rone\r\n" {
		t.Fatalf("got %q, want the body carried through unchanged", got)
	}
	if d.smuggled {
		t.Fatal("a conforming <CRLF>.<CRLF> was flagged as smuggled")
	}
}

// A bare <LF>.<LF> must not hand the stream back to the command loop: that is
// what turns control of a message body into control of the envelope. The body
// is still yielded -- the message is accepted -- but smuggled is set so the
// session closes instead of executing what follows.
func TestDotReaderFlagsNonConformingEndOfData(t *testing.T) {
	cases := []struct {
		name, input, wantBody string
		wantSmuggled          bool
	}{
		{"conforming", "body\r\n.\r\n", "body\r\n", false},
		{"bare LF throughout", "body\n.\n", "body\r\n", true},
		{"LF before a CRLF dot", "body\n.\r\n", "body\r\n", true},
		{"CRLF before a bare LF dot", "body\r\n.\n", "body\r\n", true},
		{"empty message", ".\r\n", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader(tc.input + "MAIL FROM:<x@y.de>\r\n"))
			d := newDotReader(br)
			got, err := io.ReadAll(d)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != tc.wantBody {
				t.Fatalf("body %q, want %q", got, tc.wantBody)
			}
			if d.smuggled != tc.wantSmuggled {
				t.Fatalf("smuggled = %v, want %v", d.smuggled, tc.wantSmuggled)
			}
			// Whatever follows the dot is still sitting in the reader either
			// way; what changes is whether the caller goes back to it.
			rest, err := readStructuredLine(br, maxLineOctet)
			if err != nil || rest != "MAIL FROM:<x@y.de>" {
				t.Fatalf("trailing input = %q, %v", rest, err)
			}
		})
	}
}

// withdraw un-queues copies committed earlier in the same transaction. A copy
// is claimable the instant Commit returns, so by the time a later copy fails
// and withdraw runs, the withdrawn copy's own history row already exists and
// must be updated to removed -- left as "queued" it would stay listed forever
// for a message the spool no longer holds.
func TestWithdrawMarksSpoolCopiesRemoved(t *testing.T) {
	sp, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "history.db"), discardLog(), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	s := &session{srv: &Server{spool: sp, store: st}, log: discardLog()}

	staged, err := sp.Stage(strings.NewReader("Subject: t\r\n\r\nbody\r\n"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer staged.Discard()

	var ids []spool.ID
	for i := 0; i < 2; i++ {
		now := time.Now().UTC()
		env := spool.Envelope{
			From: "device@example.at", To: []string{"ops@example.net"},
			Origin: "printers", Route: "r", Received: now,
		}
		id, err := sp.Commit(staged, env, time.Hour, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.RecordMessage(store.MessageRecord{
			QueueID: id.String(), Client: "printers", Route: "r",
			EnvelopeFrom: "device@example.at", Recipients: []string{"ops@example.net"},
			Listener: "l", RemoteAddr: "127.0.0.1", ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	s.withdraw(ids)

	if n := sp.Len(); n != 0 {
		t.Errorf("sp.Len() = %d after withdraw, want 0", n)
	}
	for _, id := range ids {
		msg, err := st.FindMessageByID(id.String())
		if err != nil {
			t.Fatalf("FindMessageByID(%s): %v", id, err)
		}
		if msg == nil {
			t.Fatalf("no history row for %s", id)
		}
		if msg.Status != store.StatusRemoved {
			t.Errorf("%s: Status = %q, want %q", id, msg.Status, store.StatusRemoved)
		}
	}
}
