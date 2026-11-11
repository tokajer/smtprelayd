// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package spool

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/queueid"
)

// pathOf is the absolute path of a root-relative spool name, for tests that
// inspect or tamper with the directory from outside the Spool.
func (s *Spool) pathOf(name string) string {
	return filepath.Join(s.root.Name(), filepath.FromSlash(name))
}

// openForTest opens a spool in dir and closes it when the test ends.
func openForTest(t *testing.T, dir string) *Spool {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// fixedID is a valid queue id for tests that need one without a spool.
const fixedID = queueid.ID("ABCDEFGHIJKLMNOP")

// listenerEnvelope has the shape session.commitCopies writes.
func listenerEnvelope() Envelope {
	return Envelope{
		From:         "relay@example.at",
		To:           []string{"ops@example.net", "\"quoted local\"@example.net", "ümlaut@example.net"},
		OriginalFrom: "scanner@printer.local",
		Origin:       "printers",
		Route:        "m365 primary",
		Listener:     "internal",
		RemoteAddr:   "[fe80::1%eth0]:41234",
		Helo:         "printer-3.local\a",
		TLS:          true,
		Received:     time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC),
	}
}

// selfmailEnvelope has the shape selfmail.Mailer.Send writes: the null
// reverse path and the fixed internal peer.
func selfmailEnvelope() Envelope {
	return Envelope{
		From:       "",
		To:         []string{"ops@example.at"},
		Origin:     "bounce-notifier",
		Route:      "m365",
		Listener:   "bounce-notifier",
		RemoteAddr: "internal",
		Received:   time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC),
		Kind:       KindNotification,
	}
}

func validMeta() *Meta {
	m := &Meta{ID: fixedID, Envelope: listenerEnvelope(), Attempts: 2, LastError: "451 4.7.0 try later\r\n"}
	m.Envelope.normalizeKind()
	return m
}

func TestValidateRefusesWhatTheRelayCannotHaveWritten(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m *Meta)
	}{
		{"CRLF in from", func(m *Meta) { m.Envelope.From = "a@example.at\r\nRCPT TO:<x@evil.example>" }},
		{"NUL in from", func(m *Meta) { m.Envelope.From = "a\x00@example.at" }},
		{"from without domain", func(m *Meta) { m.Envelope.From = "a@" }},
		{"from longer than 254", func(m *Meta) { m.Envelope.From = strings.Repeat("a", 64) + "@" + strings.Repeat("b", 190) + ".at" }},
		{"LF in original_from", func(m *Meta) { m.Envelope.OriginalFrom = "a@example.at\nBcc: x@evil.example" }},
		{"no recipient", func(m *Meta) { m.Envelope.To = nil }},
		{"empty recipient", func(m *Meta) { m.Envelope.To = []string{"ops@example.net", ""} }},
		{"CRLF in recipient", func(m *Meta) { m.Envelope.To = []string{"ops@example.net\r\nDATA"} }},
		{"ESC in recipient", func(m *Meta) { m.Envelope.To = []string{"ops\x1b@example.net"} }},
		{"DEL in recipient", func(m *Meta) { m.Envelope.To = []string{"ops\x7f@example.net"} }},
		{"recipient with dotted domain edge", func(m *Meta) { m.Envelope.To = []string{"ops@.example.net"} }},
		{"empty route", func(m *Meta) { m.Envelope.Route = "" }},
		{"CRLF in route", func(m *Meta) { m.Envelope.Route = "m365\r\n" }},
		{"quote in route", func(m *Meta) { m.Envelope.Route = `m"365` }},
		{"backslash in route", func(m *Meta) { m.Envelope.Route = `m\365` }},
		{"8-bit route", func(m *Meta) { m.Envelope.Route = "m365é" }},
		{"route longer than 64", func(m *Meta) { m.Envelope.Route = strings.Repeat("r", 65) }},
		{"control in origin", func(m *Meta) { m.Envelope.Origin = "printers\n" }},
		{"origin longer than 64", func(m *Meta) { m.Envelope.Origin = strings.Repeat("o", 65) }},
		{"control in listener", func(m *Meta) { m.Envelope.Listener = "int\x00ernal" }},
		{"control in remote_addr", func(m *Meta) { m.Envelope.RemoteAddr = "10.0.0.1:25\r\n" }},
		{"remote_addr longer than 512", func(m *Meta) { m.Envelope.RemoteAddr = strings.Repeat("1", 513) }},
		{"CRLF in helo", func(m *Meta) { m.Envelope.Helo = "printer\r\nMAIL FROM:<x@evil.example>" }},
		{"NUL in helo", func(m *Meta) { m.Envelope.Helo = "printer\x00" }},
		{"helo longer than 512", func(m *Meta) { m.Envelope.Helo = strings.Repeat("h", 513) }},
		{"unknown kind", func(m *Meta) { m.Envelope.Kind = "bounce" }},
		{"negative size", func(m *Meta) { m.Envelope.Size = -1 }},
		{"negative attempts", func(m *Meta) { m.Attempts = -1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := validMeta()
			c.mutate(m)
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeMeta(b, fixedID); !errors.Is(err, ErrInvalidMeta) {
				t.Errorf("decodeMeta error = %v, want ErrInvalidMeta", err)
			}

			s := openForTest(t, t.TempDir())
			if err := s.writeMeta(m); !errors.Is(err, ErrInvalidMeta) {
				t.Errorf("writeMeta error = %v, want ErrInvalidMeta", err)
			}
			if _, err := os.Stat(s.pathOf(metaName(fixedID))); !os.IsNotExist(err) {
				t.Errorf("writeMeta left a metadata file behind: %v", err)
			}
		})
	}
}

// Both shapes the relay itself writes have to survive the check on the way
// out and on the way back in, field for field.
func TestRealEnvelopesRoundTrip(t *testing.T) {
	for name, env := range map[string]Envelope{
		"listener": listenerEnvelope(),
		"selfmail": selfmailEnvelope(),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s := openForTest(t, dir)
			id, err := s.Enqueue(env, strings.NewReader("Subject: x\r\n\r\nbody\r\n"), 0, time.Hour)
			if err != nil {
				t.Fatalf("Enqueue: %v", err)
			}
			_ = s.Close()
			reopened := openForTest(t, dir)
			m, ok := reopened.Claim(time.Now())
			if !ok || m.ID != id {
				t.Fatalf("message did not survive a restart: %v %v", m, ok)
			}
			want := env
			want.Size = m.Envelope.Size
			want.normalizeKind()
			if !reflect.DeepEqual(m.Envelope, want) {
				t.Errorf("envelope changed across a restart:\n got %+v\nwant %+v", m.Envelope, want)
			}
		})
	}
}

// A commit whose envelope fails the check is refused before anything is
// visible, and the queue directory is left as it was.
func TestCommitRefusesAnInvalidEnvelope(t *testing.T) {
	s := openForTest(t, t.TempDir())
	env := listenerEnvelope()
	env.To = []string{"ops@example.net\r\nRCPT TO:<x@evil.example>"}
	if _, err := s.Enqueue(env, strings.NewReader("body"), 0, time.Hour); !errors.Is(err, ErrInvalidMeta) {
		t.Fatalf("Enqueue error = %v, want ErrInvalidMeta", err)
	}
	if n := s.Len(); n != 0 {
		t.Errorf("index holds %d messages after a refused commit", n)
	}
	for _, dir := range []string{queueDir, tmpDir} {
		entries, err := os.ReadDir(s.pathOf(dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			t.Errorf("%s still holds %s after a refused commit", dir, e.Name())
		}
	}
}

// An address that passes validate as written but not as json.Marshal
// encodes it -- each invalid UTF-8 octet becomes three -- must get one
// verdict, on the way out and at the next start. writeMeta checks the
// encoding, so the commit is refused rather than accepted and quarantined
// after a restart.
func TestWriteAndReadAgreeOnInvalidUTF8(t *testing.T) {
	dir := t.TempDir()
	s := openForTest(t, dir)
	env := listenerEnvelope()
	env.To = []string{strings.Repeat("\xff", 30) + "@example.net"}
	if err := (&Meta{ID: fixedID, Envelope: env}).validate(); err != nil {
		t.Fatalf("precondition: the raw address should pass validate: %v", err)
	}
	if _, err := s.Enqueue(env, strings.NewReader("body"), 0, time.Hour); !errors.Is(err, ErrInvalidMeta) {
		t.Fatalf("Enqueue error = %v, want ErrInvalidMeta", err)
	}
	_ = s.Close()
	reopened := openForTest(t, dir)
	if reopened.Len() != 0 || len(reopened.Quarantined()) != 0 {
		t.Errorf("a refused commit left something for the next start: len=%d quarantined=%v",
			reopened.Len(), reopened.Quarantined())
	}
}

func TestMetadataSizeIsBounded(t *testing.T) {
	s := openForTest(t, t.TempDir())
	id := enqueueOneForTest(t, s)

	m := validMeta()
	m.ID = id
	m.LastError = strings.Repeat("x", maxMetaBytes)
	if err := s.writeMeta(m); !errors.Is(err, ErrInvalidMeta) {
		t.Errorf("writeMeta of an oversized encoding: error = %v, want ErrInvalidMeta", err)
	}

	// Written past writeMeta, the way only something other than the relay
	// could: well-formed and for the right message, just too large to read.
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.pathOf(metaName(id)), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readMeta(id); !errors.Is(err, ErrInvalidMeta) {
		t.Errorf("readMeta of a %d octet file: error = %v, want ErrInvalidMeta", len(b), err)
	}
}

// A newer binary may add keys; one rolled back to this version has to go on
// reading its metadata.
func TestDecodeMetaIgnoresUnknownKeys(t *testing.T) {
	b, err := json.Marshal(validMeta())
	if err != nil {
		t.Fatal(err)
	}
	b = append([]byte(`{"future":{"nested":[1,2]},`), b[1:]...)
	if _, err := decodeMeta(b, fixedID); err != nil {
		t.Fatalf("decodeMeta refused an unknown key: %v", err)
	}
}

// Metadata that parses, for the right message, but fails validate is moved
// to spool/failed with its body: never indexed, never deleted, refused by
// Requeue on the same check and removable by Discard.
func TestRecoverQuarantinesInvalidMetadata(t *testing.T) {
	dir := t.TempDir()
	s := openForTest(t, dir)
	id, err := s.Enqueue(listenerEnvelope(), strings.NewReader("body"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m := validMeta()
	m.ID = id
	m.Envelope.To = []string{"ops@example.net\r\nRCPT TO:<x@evil.example>"}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.pathOf(metaName(id)), b, 0o600); err != nil {
		t.Fatal(err)
	}

	_ = s.Close()
	reopened := openForTest(t, dir)
	if n := reopened.Len(); n != 0 {
		t.Fatalf("invalid metadata was indexed: %d live messages", n)
	}
	if got := reopened.Quarantined(); len(got) != 1 || got[0] != id {
		t.Errorf("Quarantined() = %v, want [%s]", got, id)
	}
	if _, ok := reopened.Claim(time.Now()); ok {
		t.Fatal("invalid metadata was claimable")
	}
	for _, ext := range []string{".json", ".eml"} {
		if _, err := os.Stat(reopened.pathOf(fileName(queueDir, id, ext))); !os.IsNotExist(err) {
			t.Errorf("queue/%s%s is still there: %v", id, ext, err)
		}
		if _, err := os.Stat(reopened.pathOf(fileName(failedDir, id, ext))); err != nil {
			t.Errorf("failed/%s%s was not kept: %v", id, ext, err)
		}
	}
	if !reopened.Has(id) || reopened.failed.occupied() == 0 {
		t.Errorf("quarantined message is not accounted for: has=%v occupied=%d",
			reopened.Has(id), reopened.failed.occupied())
	}

	if err := reopened.Requeue(id, nil); !errors.Is(err, ErrInvalidMeta) {
		t.Errorf("Requeue of a quarantined message: error = %v, want ErrInvalidMeta", err)
	}
	if reopened.Len() != 0 {
		t.Error("a refused Requeue indexed the message anyway")
	}
	if err := reopened.Discard(id); err != nil {
		t.Errorf("Discard of a quarantined message: %v", err)
	}
	if reopened.Has(id) {
		t.Error("a discarded quarantined message is still reported")
	}
}

// invalidPairForTest commits a message and then replaces its metadata with a
// well-formed file that validate refuses, the shape recover quarantines.
func invalidPairForTest(t *testing.T, s *Spool) queueid.ID {
	t.Helper()
	id := enqueueOneForTest(t, s)
	m := validMeta()
	m.ID = id
	m.Envelope.Route = `m"365`
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.pathOf(metaName(id)), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return id
}

// A quarantine that cannot move both files moves neither. Either half alone
// is lost evidence: metadata in spool/failed without its body, or a body in
// the queue directory without metadata, which the next start deletes. The
// pair stays where it was, unindexed, and the next start tries again.
func TestQuarantineMovesBothFilesOrNeither(t *testing.T) {
	for _, blocked := range []string{".json", ".eml"} {
		t.Run(blocked, func(t *testing.T) {
			dir := t.TempDir()
			s := openForTest(t, dir)
			id := invalidPairForTest(t, s)
			obstruction := s.pathOf(fileName(failedDir, id, blocked))
			obstruct(t, obstruction)
			_ = s.Close()

			reopened := openForTest(t, dir)
			if n := reopened.Len(); n != 0 {
				t.Errorf("invalid metadata was indexed: %d live messages", n)
			}
			if got := reopened.Quarantined(); len(got) != 0 {
				t.Errorf("Quarantined() = %v for a move that did not happen", got)
			}
			for _, ext := range []string{".json", ".eml"} {
				if _, err := os.Stat(reopened.pathOf(fileName(queueDir, id, ext))); err != nil {
					t.Errorf("queue/%s%s did not stay in place: %v", id, ext, err)
				}
			}
			other := map[string]string{".json": ".eml", ".eml": ".json"}[blocked]
			if _, err := os.Stat(reopened.pathOf(fileName(failedDir, id, other))); !os.IsNotExist(err) {
				t.Errorf("failed/%s%s was moved without its other half: %v", id, other, err)
			}
			_ = reopened.Close()

			if err := os.RemoveAll(obstruction); err != nil {
				t.Fatal(err)
			}
			if got := openForTest(t, dir).Quarantined(); len(got) != 1 || got[0] != id {
				t.Errorf("the next start did not quarantine the pair: Quarantined() = %v", got)
			}
		})
	}
}

// Metadata that does not decode at all keeps the older treatment: not
// indexed, body removed, nothing moved to spool/failed.
func TestRecoverDoesNotQuarantineUnparsableMetadata(t *testing.T) {
	dir := t.TempDir()
	s := openForTest(t, dir)
	id := enqueueOneForTest(t, s)
	if err := os.WriteFile(s.pathOf(metaName(id)), []byte(`{"id":`), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	reopened := openForTest(t, dir)
	if reopened.Len() != 0 || reopened.Has(id) {
		t.Fatalf("unparsable metadata was kept: len=%d has=%v", reopened.Len(), reopened.Has(id))
	}
	if _, err := os.Stat(reopened.pathOf(fileName(failedDir, id, ".json"))); !os.IsNotExist(err) {
		t.Errorf("unparsable metadata was quarantined: %v", err)
	}
}

// plantSymlink moves the spool file name to dst and leaves a symlink to it,
// spelled target, in its place, so that a followed link would read perfectly
// good content. The returned function puts the real file back.
func plantSymlink(t *testing.T, s *Spool, name, dst, target string) (restore func()) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs a privilege the Windows runner lacks; the data directory ACL covers reparse points there")
	}
	real := s.pathOf(name)
	if err := os.Rename(real, dst); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, real); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Remove(real); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(dst, real); err != nil {
			t.Fatal(err)
		}
	}
}

// A symlink at a message's metadata or body is refused, whether it points
// inside the spool directory, which os.Root alone would follow, or outside
// it.
func TestSymlinksInTheQueueAreRefused(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside")
	for _, c := range []struct {
		name string
		// dst is where the real file goes, target how the link names it.
		place func(s *Spool) (dst, target string)
	}{
		{"inside the spool", func(s *Spool) (string, string) {
			return s.pathOf(queueDir + "/elsewhere"), "elsewhere"
		}},
		{"outside, relative", func(s *Spool) (string, string) {
			rel, err := filepath.Rel(s.pathOf(queueDir), outside)
			if err != nil {
				t.Fatal(err)
			}
			return outside, rel
		}},
		{"outside, absolute", func(s *Spool) (string, string) {
			return outside, outside
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			s := openForTest(t, dir)
			id := enqueueOneForTest(t, s)
			dst, target := c.place(s)

			restore := plantSymlink(t, s, metaName(id), dst, target)
			if _, err := s.readMeta(id); !errors.Is(err, errNotRegular) {
				t.Errorf("readMeta through a symlink to %s: error = %v, want a refusal", target, err)
			}
			restore()

			restore = plantSymlink(t, s, dataName(id), dst, target)
			if f, err := s.OpenBody(id); err == nil {
				_ = f.Close()
				t.Errorf("OpenBody followed a symlink to %s", target)
			}
			restore()

			// And at startup: metadata behind a symlink is not indexed.
			plantSymlink(t, s, metaName(id), dst, target)
			_ = s.Close()
			if n := openForTest(t, dir).Len(); n != 0 {
				t.Errorf("metadata behind a symlink to %s was indexed at startup", target)
			}
		})
	}
}
