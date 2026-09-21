// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/certgen"
	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// Nothing in this package drove an actual SMTP transaction, so every verb
// handler sat at 0% coverage and each of the session's refusals could be
// deleted with the whole suite still green -- the open-relay refusal
// included. These tests speak the protocol over a real socket, which is the
// only way to reach doMail at all.

// smtpConn is a client dialogue against a bound listener.
type smtpConn struct {
	t  *testing.T
	c  net.Conn
	br *bufio.Reader
}

// reply reads one complete SMTP reply and returns its final line. A
// multiline reply keeps a hyphen after the code until the last line.
func (s *smtpConn) reply() string {
	s.t.Helper()
	for {
		line, err := s.br.ReadString('\n')
		if err != nil {
			s.t.Fatalf("reading a reply: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 || line[3] != '-' {
			return line
		}
	}
}

func (s *smtpConn) send(format string, a ...any) {
	s.t.Helper()
	if _, err := fmt.Fprintf(s.c, format+"\r\n", a...); err != nil {
		s.t.Fatalf("writing %q: %v", format, err)
	}
}

// sendMayFail writes a line the server may already have closed on. Its two
// callers are testing exactly that: the server refuses and stops reading
// without waiting for the rest of the transfer, so the write losing a race
// with the close is the behaviour under test, not a failure. The assertion is
// what comes back, not whether the bytes went out.
func (s *smtpConn) sendMayFail(format string, a ...any) {
	s.t.Helper()
	_, _ = fmt.Fprintf(s.c, format+"\r\n", a...)
}

// expect asserts the enhanced status code the next reply carries.
func (s *smtpConn) expect(what, code string) string {
	s.t.Helper()
	got := s.reply()
	if !strings.HasPrefix(got, code) {
		s.t.Fatalf("%s: got %q, want a %s reply", what, got, code)
	}
	return got
}

func (s *smtpConn) startTLS(host string, pool *tls.Config) {
	s.t.Helper()
	s.send("STARTTLS")
	s.expect("STARTTLS", "220")
	tc := tls.Client(s.c, pool)
	if err := tc.Handshake(); err != nil {
		s.t.Fatalf("client handshake: %v", err)
	}
	s.c, s.br = tc, bufio.NewReader(tc)
}

// serveTest binds one listener from cfg, runs it until the test ends, and
// returns a dialogue that has already read the banner.
func serveTest(t *testing.T, cfg *config.Config) *smtpConn {
	t.Helper()
	cfg.Listeners[0].Address = "127.0.0.1:0"
	if cfg.Limits.MaxConnections == 0 {
		cfg.Limits.MaxConnections = 10
	}
	set, err := New(cfg, nil, discardLog(), nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := set.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { set.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancellation")
		}
	})

	conn, err := net.DialTimeout("tcp", set.servers[0].ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	s := &smtpConn{t: t, c: conn, br: bufio.NewReader(conn)}
	s.expect("banner", "220")
	return s
}

func plainConfig(clients ...config.Client) *config.Config {
	return &config.Config{
		Service:   config.Service{Hostname: "relay.test"},
		Listeners: []config.Listener{{Name: "test", TLS: "none"}},
		Clients:   clients,
		Limits:    config.Limits{MaxConnections: 10, MaxMessageMB: 1},
	}
}

// localClient allowlists the loopback address the test dials from.
func localClient() config.Client {
	return config.Client{Name: "local", CIDR: []string{"127.0.0.0/8"}}
}

// The one guarantee docs/guides/SECURITY.md says cannot be recovered from
// cheaply: a source outside every client CIDR must never be able to relay.
// Matcher.Match not matching is tested separately; this is the other half,
// that the session then refuses.
func TestUnmatchedSourceCannotRelay(t *testing.T) {
	s := serveTest(t, plainConfig())
	s.send("EHLO probe.test")
	s.expect("EHLO", "250")
	s.send("MAIL FROM:<anyone@example.test>")
	if got := s.expect("MAIL FROM from an unmatched source", "550"); !strings.Contains(got, "5.7.1") {
		t.Errorf("refusal was %q, want the 5.7.1 relay-denied status", got)
	}
}

func TestMailBeforeHeloIsRefused(t *testing.T) {
	s := serveTest(t, plainConfig(localClient()))
	s.send("MAIL FROM:<device@example.test>")
	s.expect("MAIL FROM before EHLO", "503")
}

// An allowlisted client is refused a message it announces as too large
// before it sends a byte of it, rather than after the transfer.
func TestDeclaredSizeOverTheLimitIsRefused(t *testing.T) {
	s := serveTest(t, plainConfig(localClient()))
	s.send("EHLO probe.test")
	s.expect("EHLO", "250")
	s.send("MAIL FROM:<device@example.test> SIZE=99999999")
	if got := s.expect("oversized SIZE", "552"); !strings.Contains(got, "5.3.4") {
		t.Errorf("refusal was %q, want the 5.3.4 size status", got)
	}
}

// require_tls must be enforced at MAIL FROM, not merely advertised: an
// allowlisted client that skips STARTTLS is refused, and the same client is
// accepted once the handshake has happened.
func TestRequireTLSIsEnforcedAtMailFrom(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, err := certgen.Generate(certgen.Options{Hosts: []string{"127.0.0.1", "relay.test"}})
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := plainConfig(localClient())
	cfg.Listeners[0].TLS = "starttls"
	cfg.Listeners[0].RequireTLS = true
	cfg.TLS = config.TLS{CertFile: certFile, KeyFile: keyFile}

	s := serveTest(t, cfg)
	s.send("EHLO probe.test")
	s.expect("EHLO", "250")
	s.send("MAIL FROM:<device@example.test>")
	if got := s.expect("MAIL FROM without TLS", "530"); !strings.Contains(got, "5.7.0") {
		t.Errorf("refusal was %q, want the 5.7.0 STARTTLS-required status", got)
	}

	// The certificate is self-signed and this is the listener's own, so the
	// probe pins nothing and skips chain verification deliberately.
	s.startTLS("127.0.0.1", &tls.Config{InsecureSkipVerify: true, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}) //#nosec G402 -- dialing this test's own listener
	s.send("EHLO probe.test")
	s.expect("EHLO after STARTTLS", "250")
	s.send("MAIL FROM:<device@example.test>")
	s.expect("MAIL FROM over TLS", "250")
}

// serveQueued is serveTest with a real spool and history store, which doData
// needs as soon as a message is actually committed.
func serveQueued(t *testing.T, cfg *config.Config) *smtpConn {
	t.Helper()
	s, _ := serveQueuedWithStore(t, cfg)
	return s
}

// serveQueuedWithStore is serveQueued for a test that also has to read back
// what was journalled.
func serveQueuedWithStore(t *testing.T, cfg *config.Config) (*smtpConn, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	sp, err := spool.Open(dir)
	if err != nil {
		t.Fatalf("spool.Open: %v", err)
	}
	st, err := store.Open(dir, discardLog(), 90, true)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg.Listeners[0].Address = "127.0.0.1:0"
	set, err := New(cfg, sp, discardLog(), st, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := set.Bind(); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { set.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancellation")
		}
	})

	conn, err := net.DialTimeout("tcp", set.servers[0].ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	s := &smtpConn{t: t, c: conn, br: bufio.NewReader(conn)}
	s.expect("banner", "220")
	return s, st
}

// queueConfig is plainConfig plus the route a committed message needs.
func queueConfig() *config.Config {
	cfg := plainConfig(config.Client{Name: "local", CIDR: []string{"127.0.0.0/8"}, Route: "r"})
	cfg.Routes = []config.Route{{Name: "r", Default: true, Host: "smtp.example", Port: 587, Auth: "none", TLS: "none"}}
	cfg.Queue = config.Queue{MaxLifetimeHours: 1}
	cfg.Limits.MaxHops = 2
	cfg.Limits.MaxHeaders = 50
	cfg.Limits.MaxHeaderBytes = 65536
	cfg.Limits.DataTimeoutSec = 30
	return cfg
}

func (s *smtpConn) beginData() {
	s.t.Helper()
	s.send("EHLO probe.test")
	s.expect("EHLO", "250")
	s.send("MAIL FROM:<device@example.test>")
	s.expect("MAIL FROM", "250")
	s.send("RCPT TO:<ops@example.test>")
	s.expect("RCPT TO", "250")
	s.send("DATA")
	s.expect("DATA", "354")
}

// A message carrying as many Received headers as limits.max_hops is refused:
// that many hops means the message is going round a loop, and accepting it
// keeps the loop running.
func TestHopLimitIsEnforced(t *testing.T) {
	s := serveQueued(t, queueConfig())
	s.beginData()
	s.send("Received: from a by b; Mon, 1 Jan 2026 00:00:00 +0000")
	s.send("Received: from c by d; Mon, 1 Jan 2026 00:00:01 +0000")
	s.send("Subject: looping")
	// The blank line ends the header block, which is where scanHeaders
	// returns and the hop count is judged: the refusal comes before the body
	// is ever asked for. Sending one anyway raced the server's close and made
	// this test fail under load roughly once in fifty runs.
	s.send("")
	if got := s.expect("a message at the hop limit", "554"); !strings.Contains(got, "5.4.6") {
		t.Errorf("refusal was %q, want the 5.4.6 hop status", got)
	}
}

// SMTP smuggling: a body ended with a bare-LF dot is queued -- a legacy
// device must not be told its message was lost -- but whatever follows the
// dot was chosen by whoever wrote the body, so the session must not go back
// to reading commands from it. Anything else lets one submission inject a
// second envelope past the allowlist.
func TestSmuggledEndOfDataClosesTheSession(t *testing.T) {
	s := serveQueued(t, queueConfig())
	s.beginData()
	s.send("Subject: carrier")
	s.send("")
	// "body\r\n.\n": a bare-LF dot line, with a second envelope behind it.
	if _, err := fmt.Fprint(s.c, "body\r\n.\n"); err != nil {
		t.Fatal(err)
	}

	// The carrier's reply is read first. The session closes right after it,
	// and a close with unread client data in the socket sends an RST that can
	// discard the reply still sitting in this side's buffer -- which made the
	// assertion below fail for a reason that has nothing to do with
	// smuggling. Reading first costs nothing: the property under test is that
	// the session does not go back to reading commands, and the two lines
	// below still prove it.
	s.expect("the carrier message", "250")

	s.sendMayFail("MAIL FROM:<smuggled@example.test>")
	s.sendMayFail("RCPT TO:<victim@example.test>")

	_ = s.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := s.br.ReadString('\n')
	if err == nil {
		t.Fatalf("the session answered %q after a smuggled end of data instead of closing", strings.TrimRight(line, "\r\n"))
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the session neither answered nor closed after a smuggled end of data")
	}
}

// deadConn accepts commands forever and fails every write, which is what a
// peer that has gone away looks like from the server's side once its own
// socket buffer has drained.
type deadConn struct{ net.Conn }

func (deadConn) Read(p []byte) (int, error)         { return copy(p, "NOOP\r\n"), nil }
func (deadConn) Write([]byte) (int, error)          { return 0, errors.New("connection reset by peer") }
func (deadConn) SetDeadline(time.Time) error        { return nil }
func (deadConn) SetReadDeadline(t time.Time) error  { return nil }
func (deadConn) SetWriteDeadline(t time.Time) error { return nil }
func (deadConn) Close() error                       { return nil }

// A session whose replies cannot be written must end rather than keep
// reading. It used to run until the read deadline expired -- a full
// read_timeout_sec, sixty seconds by default -- holding a connection slot
// against a peer that was already gone, and a client that hangs up after
// every command could hold every slot that way.
func TestSessionEndsWhenItsRepliesCannotBeWritten(t *testing.T) {
	cfg := &config.Config{
		Service: config.Service{Hostname: "relay.test"},
		Limits:  config.Limits{ReadTimeoutSec: 60, WriteTimeoutSec: 60, MaxMessageMB: 10},
	}
	srv := &Server{cfg: cfg, lc: config.Listener{Name: "smtp", TLS: config.TLSNone}, log: discardLog()}
	conn := deadConn{}
	s := &session{
		srv: srv, ctx: context.Background(), conn: conn,
		br: bufio.NewReader(conn), bw: bufio.NewWriter(conn),
		clientBits: -1, log: discardLog(),
	}

	done := make(chan struct{})
	go func() {
		s.reply(220, "relay.test ESMTP smtprelayd")
		s.loop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the session is still reading from a connection it cannot answer")
	}
	if !s.writeFailed {
		t.Error("the failed write was not recorded")
	}
}

// A message whose recipients split across two routes becomes two queued
// copies, and the journal metadata read out of the header block has to be
// identical on both: it describes the message, not the copy.
//
// This is what makes hoisting the four reads out of the per-group loop safe.
// journalAccepted used to do them itself, and rewrite.HeaderValue and
// rewrite.HeaderCount each parse the whole block, so this message cost eight
// parses where it now costs one. Nothing about the recorded row may change
// with it.
func TestJournalMetadataIsIdenticalForEveryRouteCopy(t *testing.T) {
	cfg := queueConfig()
	// The subject is only read when history.retain_subjects is on, which is
	// the shipped default; queueConfig leaves the whole History block zero.
	cfg.History.RetainSubjects = true
	cfg.Routes = []config.Route{
		{Name: "r", Default: true, Host: "smtp.example", Port: 587, Auth: "none", TLS: "none"},
		{Name: "partner", Host: "smtp.partner.example", Port: 587, Auth: "none", TLS: "none",
			Domains: []string{"partner.example"}},
	}
	s, st := serveQueuedWithStore(t, cfg)

	s.send("EHLO probe.test")
	s.expect("EHLO", "250")
	s.send("MAIL FROM:<device@example.test>")
	s.expect("MAIL FROM", "250")
	s.send("RCPT TO:<ops@example.test>")
	s.expect("RCPT TO default route", "250")
	s.send("RCPT TO:<someone@partner.example>")
	s.expect("RCPT TO partner route", "250")
	s.send("DATA")
	s.expect("DATA", "354")

	s.send("Subject: quarterly scan")
	s.send("Message-ID: <abc123@device.example>")
	s.send("Content-Type: text/plain; charset=utf-8")
	s.send("X-Device: scanner-4")
	s.send("")
	s.send("body")
	s.send(".")
	accepted := s.expect("end of data", "250")

	// Two copies, named in the acceptance reply: "queued as <id> <id>".
	fields := strings.Fields(accepted)
	ids := fields[len(fields)-2:]
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatalf("expected two distinct queue ids in %q", accepted)
	}

	var first *store.Message
	for _, id := range ids {
		msg, err := st.FindMessageByID(id)
		if err != nil {
			t.Fatalf("FindMessageByID(%s): %v", id, err)
		}
		if msg == nil {
			t.Fatalf("no history row for %s", id)
		}
		if first == nil {
			first = msg
			// The values themselves, once: a test that only compared the two
			// copies would pass just as well if both were empty.
			if msg.Subject != "quarterly scan" {
				t.Errorf("Subject = %q, want %q", msg.Subject, "quarterly scan")
			}
			if msg.MessageID != "<abc123@device.example>" {
				t.Errorf("MessageID = %q", msg.MessageID)
			}
			if msg.ContentType != "text/plain; charset=utf-8" {
				t.Errorf("ContentType = %q", msg.ContentType)
			}
			// The four headers sent. The relay's own Received header is not
			// among them: Commit prepends it per copy, so it is not part of
			// the rewritten block these values are read from -- which is
			// also why the count can be shared between the copies at all.
			if msg.HeaderCount != 4 {
				t.Errorf("HeaderCount = %d, want 4", msg.HeaderCount)
			}
			continue
		}
		if msg.Subject != first.Subject || msg.MessageID != first.MessageID ||
			msg.ContentType != first.ContentType || msg.HeaderCount != first.HeaderCount {
			t.Errorf("copy %s journalled different metadata than %s:\n %+v\n %+v",
				msg.QueueID, first.QueueID, msg, first)
		}
		// And the copies do differ where they should.
		if msg.Route == first.Route {
			t.Errorf("both copies went to route %q; the recipients did not split", msg.Route)
		}
	}
}
