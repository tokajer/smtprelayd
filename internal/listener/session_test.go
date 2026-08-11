// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
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

func TestTimeoutFallsBackOnNonPositiveValues(t *testing.T) {
	s := &session{}
	for _, sec := range []int{0, -1} {
		if d := s.timeout(sec); d != 60*time.Second {
			t.Errorf("timeout(%d) = %v, want the 60s fallback", sec, d)
		}
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
	d := &dotReader{br: bufio.NewReader(strings.NewReader("line\rone\r\n.\r\n"))}
	got, err := io.ReadAll(d)
	if err != nil {
		t.Fatalf("body with a bare CR was rejected: %v", err)
	}
	if string(got) != "line\rone\r\n" {
		t.Fatalf("got %q, want the body carried through unchanged", got)
	}
}
