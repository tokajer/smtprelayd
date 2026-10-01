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
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/queueid"
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
	// The session no longer falls back to a built-in default for the read,
	// write and data timeouts or a client's max_recipients: config.Normalize
	// is the only place those defaults are applied now, and a config built by
	// hand (as every test here does) has to call it itself, the way
	// config.Load already does through Validate.
	cfg.Normalize()
	set, err := New(cfg, nil, nil, nil, loadTestCert(t, cfg), discardLog())
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

// loadTestCert loads the key pair cfg.TLS names, standing in for the load
// cmd/smtprelayd's loadCertificate does once at startup: listener.New takes
// an already-loaded certificate rather than a path. Returns nil when the
// config carries none, which is the common case among these tests.
func loadTestCert(t *testing.T, cfg *config.Config) *tls.Certificate {
	t.Helper()
	if cfg.TLS.CertFile == "" {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		t.Fatalf("loading the test certificate: %v", err)
	}
	return &cert
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

// serveQueuedCore is what every serveQueued* variant shares: a spool, a bound
// listener wired to the given journal and metrics registry (either may be
// nil), and a dialled connection past the banner.
func serveQueuedCore(t *testing.T, cfg *config.Config, j Journal, reg *metrics.Registry) *smtpConn {
	t.Helper()
	sp, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatalf("spool.Open: %v", err)
	}

	cfg.Listeners[0].Address = "127.0.0.1:0"
	cfg.Normalize()
	set, err := New(cfg, sp, j, reg, nil, discardLog())
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

// serveQueuedWithStore is serveQueued for a test that also has to read back
// what was journalled.
func serveQueuedWithStore(t *testing.T, cfg *config.Config) (*smtpConn, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "history.db"), discardLog(), 90, true)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return serveQueuedCore(t, cfg, st, nil), st
}

// queueConfig is plainConfig plus the route a committed message needs.
//
// Normalize is called here rather than left to serveTest/serveQueuedWithStore
// alone: the load tests in load_conc_test.go and load_degrade_test.go build
// on this and call New directly, bypassing those helpers, so this is the one
// place that reaches every caller.
func queueConfig() *config.Config {
	cfg := plainConfig(config.Client{Name: "local", CIDR: []string{"127.0.0.0/8"}, Route: "r"})
	cfg.Routes = []config.Route{{Name: "r", Default: true, Host: "smtp.example", Port: 587, Auth: "none", TLS: "none"}}
	cfg.Queue = config.Queue{MaxLifetimeHours: 1}
	cfg.Limits.MaxHops = 2
	cfg.Limits.MaxHeaders = 50
	cfg.Limits.MaxHeaderBytes = 65536
	cfg.Limits.DataTimeoutSec = 30
	cfg.Normalize()
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
		msg, err := st.FindMessageByID(queueid.ID(id))
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

// fakeJournal is a Journal that always answers err, for testing the
// journal-write-failure path without a real history store.
type fakeJournal struct{ err error }

func (f fakeJournal) RecordMessage(store.MessageRecord) error { return f.err }
func (f fakeJournal) RecordRemoval(queueid.ID) error          { return f.err }

// serveQueuedWithJournal is serveQueuedWithStore for a test that supplies its
// own Journal (a fake) instead of a real history store, and needs the
// metrics registry back to read the counters the journal path feeds.
func serveQueuedWithJournal(t *testing.T, cfg *config.Config, j Journal) (*smtpConn, *metrics.Registry) {
	t.Helper()
	reg := metrics.New(nil, nil, nil, nil)
	return serveQueuedCore(t, cfg, j, reg), reg
}

// A history journal write failure must not refuse the message: it is already
// durably queued by the time journalAccepted runs, and history is
// best-effort. Only the counter records the failure.
func TestJournalWriteFailureDoesNotRefuseTheMessage(t *testing.T) {
	s, reg := serveQueuedWithJournal(t, queueConfig(), fakeJournal{err: errors.New("db closed")})
	s.beginData()
	s.send("Subject: x")
	s.send("")
	s.send("body")
	s.send(".")
	s.expect("end of data despite the journal failure", "250")

	if got := reg.JournalWriteFailures(); got != 1 {
		t.Fatalf("JournalWriteFailures() = %d, want 1", got)
	}
}

// implicitTLSConfig builds a config with one implicit-TLS listener and a
// self-signed certificate, so a plain TCP dial that never sends a
// ClientHello reaches (*Server).handle's handshake block.
func implicitTLSConfig(t *testing.T, readTimeoutSec int) *config.Config {
	t.Helper()
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
	cfg := plainConfig()
	cfg.Listeners[0].TLS = config.TLSImplicit
	cfg.TLS = config.TLS{CertFile: certFile, KeyFile: keyFile}
	cfg.Limits.ReadTimeoutSec = readTimeoutSec
	return cfg
}

// serveImplicitTLS binds an implicit-TLS listener from cfg and returns the
// bound Set, without dialling: every test here is about a connection that
// never completes a handshake, so there is no banner to read.
func serveImplicitTLS(t *testing.T, cfg *config.Config) *Set {
	t.Helper()
	cfg.Listeners[0].Address = "127.0.0.1:0"
	cfg.Normalize()
	set, err := New(cfg, nil, nil, nil, loadTestCert(t, cfg), discardLog())
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
	return set
}

// Before this test existed, an implicit-TLS connection ran HandshakeContext
// with no deadline at all: a peer that opened the socket and never sent a
// ClientHello held it open, and the global limits.max_connections slot with
// it, forever. read_timeout_sec now bounds it the same way it bounds every
// other read in the session.
func TestImplicitTLSHandshakeHasADeadline(t *testing.T) {
	const readTimeoutSec = 1
	cfg := implicitTLSConfig(t, readTimeoutSec)
	set := serveImplicitTLS(t, cfg)

	conn, err := net.DialTimeout("tcp", set.servers[0].ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Nothing is sent: the server is left waiting for a ClientHello that
	// never arrives. The client-side deadline is well past the server bound
	// under test (read_timeout_sec, 1s here): if the server never enforced
	// its own deadline, this one fires first, and the timeout check below
	// turns that into a reported failure instead of a false pass.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	start := time.Now()
	_, readErr := conn.Read(make([]byte, 1))
	elapsed := time.Since(start)

	if readErr == nil {
		t.Fatal("the connection is still open past its read deadline; the handshake has no deadline")
	}
	var netErr net.Error
	if errors.Is(readErr, os.ErrDeadlineExceeded) || (errors.As(readErr, &netErr) && netErr.Timeout()) {
		t.Fatalf("read timed out after %v waiting on the server; the handshake deadline did not close the connection: %v", elapsed, readErr)
	}
	if want := time.Duration(readTimeoutSec)*time.Second + 2*time.Second; elapsed > want {
		t.Fatalf("connection closed after %v, want within %v of read_timeout_sec=%ds", elapsed, want, readTimeoutSec)
	}
}

// The per-source admission cap has to hold even while unmatchedMaxConns
// connections are stuck in a handshake that will never complete: before the
// admission check moved ahead of the handshake, a source exploiting the
// missing deadline was never even counted against it, since the cap was only
// reached once (a now-bounded) handshake attempt had already failed.
func TestImplicitTLSAdmissionCapHoldsDuringAStalledHandshake(t *testing.T) {
	// Large enough that a stalled handshake alone would run to the full
	// 30s: the only thing that can explain the over-cap connection closing
	// much sooner is the admission cap's own refusal, bounded by
	// refusalTimeout (5s), not read_timeout_sec.
	const readTimeoutSec = 30
	cfg := implicitTLSConfig(t, readTimeoutSec)
	set := serveImplicitTLS(t, cfg)
	addr := set.servers[0].ln.Addr().String()

	dial := func() net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	// Fill the unmatched source's admission cap with connections that never
	// send a ClientHello, then add one more: the cap is checked before the
	// handshake, so this one must be refused rather than simply becoming a
	// third stalled handshake.
	for i := 0; i < unmatchedMaxConns; i++ {
		dial()
	}
	over := dial()

	// A client-side deadline much longer than what is under test here (cap +
	// refusalTimeout = 5s): if the server never closed this connection early,
	// this fires first, and the timeout check below reports that as a
	// failure instead of a false pass.
	_ = over.SetReadDeadline(time.Now().Add(readTimeoutSec * time.Second))
	start := time.Now()
	_, err := over.Read(make([]byte, 1))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("the over-cap connection is still open; the admission cap did not close it")
	}
	var netErr net.Error
	if errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("read timed out after %v; the admission cap did not close the connection: %v", elapsed, err)
	}
	if want := 8 * time.Second; elapsed > want {
		t.Fatalf("over-cap connection closed after %v, want within %v (cap + refusalTimeout)", elapsed, want)
	}
}

// accept's global-cap refusal on an implicit-TLS listener must close the
// over-cap connection without writing: a plaintext 421 would run the TLS
// server handshake first, which blocks reading a ClientHello, and with no
// deadline on that write a silent peer at the cap would hold it -- and the
// whole accept loop behind it -- indefinitely.
func TestImplicitTLSGlobalCapRefusalDoesNotHangTheAcceptLoop(t *testing.T) {
	const readTimeoutSec = 30
	cfg := implicitTLSConfig(t, readTimeoutSec)
	cfg.Limits.MaxConnections = 1
	set := serveImplicitTLS(t, cfg)
	addr := set.servers[0].ln.Addr().String()

	// Occupy the one global slot with a connection that never sends a
	// ClientHello. The session's own handshake deadline (read_timeout_sec,
	// 30s here) keeps it open for the rest of this test, so the second dial
	// below is the one that has to hit the global cap, not a slot freed by
	// this one timing out.
	holder, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// The holder's connection must have claimed the global slot before the
	// second connection is dialled, or the second one could land in the
	// free slot instead of hitting the cap this test is about. sem is a
	// buffered channel sized to Limits.MaxConnections (1 here); accept
	// fills it synchronously, right after Accept returns and before it
	// spawns the session's goroutine, so polling its length is sufficient.
	srv := set.servers[0]
	deadline := time.Now().Add(2 * time.Second)
	for len(srv.sem) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the holder connection to claim the global slot")
		}
		time.Sleep(time.Millisecond)
	}

	over, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer over.Close()

	// A client-side deadline much longer than what is under test (a prompt
	// close): if the accept loop is stuck in a handshake write, this fires
	// first, and the timeout check below reports that as a failure instead of
	// a false pass.
	_ = over.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, readErr := over.Read(make([]byte, 1))
	elapsed := time.Since(start)

	if readErr == nil {
		t.Fatal("the over-cap connection is still open; the global cap refusal did not close it")
	}
	var netErr net.Error
	if errors.Is(readErr, os.ErrDeadlineExceeded) || (errors.As(readErr, &netErr) && netErr.Timeout()) {
		t.Fatalf("read timed out after %v; the global-cap refusal hung the accept loop instead of closing promptly: %v", elapsed, readErr)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("over-cap connection closed after %v, want promptly", elapsed)
	}

	// Free the held slot and confirm the accept loop is still servicing new
	// connections, not stuck from the refusal above.
	_ = holder.Close()

	client, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}) //#nosec G402 -- dialing this test's own listener
	if err != nil {
		t.Fatalf("the accept loop did not accept a new connection after the refusal: %v", err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	s := &smtpConn{t: t, c: client, br: bufio.NewReader(client)}
	s.expect("banner after the accept loop recovered", "220")
}

// failingQueue wraps a real *spool.Spool and forces the nth Commit call to
// fail, which is how a message that splits across routes can be driven into
// withdraw's path end to end: the first copy really lands in the spool, the
// second is refused, and withdraw has to unwind the first.
type failingQueue struct {
	*spool.Spool
	failOnCommit int // 1-based
	commits      int
}

func (q *failingQueue) Commit(st *spool.Staged, env spool.Envelope, lifetime time.Duration, prefix func(queueid.ID) string) (queueid.ID, error) {
	q.commits++
	if q.commits == q.failOnCommit {
		return "", errors.New("simulated commit failure")
	}
	return q.Spool.Commit(st, env, lifetime, prefix)
}

// The end-to-end regression test for withdraw: a message split across two
// routes whose second copy fails to commit must not leave the first copy
// queued for delivery -- that would send it once now and again when the
// client, told the whole message was refused, retries.
func TestSecondRouteCommitFailureWithdrawsTheFirstCopy(t *testing.T) {
	cfg := queueConfig()
	cfg.Routes = []config.Route{
		{Name: "r", Default: true, Host: "smtp.example", Port: 587, Auth: "none", TLS: "none"},
		{Name: "partner", Host: "smtp.partner.example", Port: 587, Auth: "none", TLS: "none",
			Domains: []string{"partner.example"}},
	}
	sp, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatalf("spool.Open: %v", err)
	}
	q := &failingQueue{Spool: sp, failOnCommit: 2}
	st, err := store.Open(filepath.Join(t.TempDir(), "history.db"), discardLog(), 90, true)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg.Listeners[0].Address = "127.0.0.1:0"
	cfg.Normalize()
	set, err := New(cfg, q, st, nil, nil, discardLog())
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
	s.send("Subject: x")
	s.send("")
	s.send("body")
	s.send(".")
	s.expect("second commit failing", "451")

	if n := sp.Len(); n != 0 {
		t.Errorf("sp.Len() = %d after a withdrawn commit, want 0", n)
	}

	msgs, _, err := st.FindMessages(store.MessageFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("history holds %d message(s), want exactly the one copy that committed", len(msgs))
	}
	if msgs[0].Status != store.StatusRemoved {
		t.Errorf("the committed-then-withdrawn copy has status %q, want %q", msgs[0].Status, store.StatusRemoved)
	}
}
