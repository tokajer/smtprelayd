// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/rewrite"
	"github.com/tokajer/smtprelayd/internal/router"
	"github.com/tokajer/smtprelayd/internal/spool"
)

const defaultMaxMessageMB = 50

// Per-session defaults applied when a client or the limits block leaves the
// value at zero. Named for the reason defaultMaxMessageMB is: an operator
// auditing what this relay enforces should find every ceiling by searching
// for its name, not by reading the function that happens to apply it.
const (
	// defaultMaxRecipients bounds one transaction when the matched client
	// sets no max_recipients of its own.
	defaultMaxRecipients = 100

	// defaultTimeoutSec is the fallback for any of the read, write and data
	// timeouts left unset.
	defaultTimeoutSec = 60
)

const (
	// unmatchedMaxConns bounds how many sockets one unauthorised source may
	// hold at a time. Such a source is refused at MAIL FROM, but the refusal
	// happens several commands in, so without a cap here it competes for the
	// global connection budget on equal terms with the devices that are
	// actually allowed to relay.
	unmatchedMaxConns = 2

	// unmatchedMaxSession is how long an unauthorised source may keep a
	// connection open. It only needs long enough to be told no; the per
	// command read deadline alone does not bound this, because every NOOP
	// resets it.
	unmatchedMaxSession = 30 * time.Second
)

type session struct {
	srv  *Server
	ctx  context.Context
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer
	log  *slog.Logger

	client     *config.Client
	clientBits int
	remote     netip.Addr
	// deadline caps the whole session, not one command. It is set only for
	// unmatched sources; an allowlisted device may legitimately hold a
	// connection open across many messages.
	deadline time.Time
	isTLS    bool
	helo     string
	from     string
	fromSet  bool
	rcpts    []string

	// writeFailed records that a reply could not be written. The peer is
	// gone or the socket is wedged, so every further command would be read
	// into a void and the session would sit there until its read deadline.
	// The loop checks this and ends instead.
	writeFailed bool
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// loop only reaches its ctx check between commands, so a session blocked
	// in a read holds shutdown for read_timeout_sec -- or data_timeout_sec
	// mid-DATA, five minutes by default. Set.Close waits on every one of
	// them, which is long past what the Windows SCM allows for a stop and
	// past systemd's default for the DATA case. Expiring the deadline on
	// cancellation ends the blocked read at once; the message was never
	// acknowledged, so the client retries and nothing is lost.
	//
	// The 421 in loop is not reached this way -- a dropped connection is what
	// the client sees. Writing it from here would race the session's own
	// writes on the same buffer.
	stopOnCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopOnCancel()

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return
	}

	ss := &session{
		srv:        s,
		ctx:        ctx,
		conn:       conn,
		br:         bufio.NewReaderSize(conn, 4096),
		bw:         bufio.NewWriter(conn),
		remote:     addr.Unmap(),
		clientBits: -1,
		log:        s.log.With("remote", host),
	}
	if tc, ok := conn.(*tls.Conn); ok {
		if err := tc.HandshakeContext(ctx); err != nil {
			ss.log.Debug("tls handshake failed", "error", err)
			return
		}
		ss.isTLS = true
	}

	// Default deny. An unmatched source is refused before it can name a
	// recipient, on every listener, regardless of TLS or authentication state.
	client, bits, matched := s.match.Match(ss.remote)
	if matched {
		key := connKeyClient(client.Name)
		if !s.conns.acquire(key, client.MaxConnections) {
			ss.reply(421, "4.7.0 too many connections for this client")
			return
		}
		defer s.conns.release(key, client.MaxConnections)
		ss.client = client
		ss.clientBits = bits
		ss.log = ss.log.With("client", client.Name)
	} else {
		// The refusal itself still happens at MAIL FROM, so that the reply
		// names the actual reason. What changes here is only how much of the
		// server an unauthorised source may occupy while getting there.
		key := connKeyUnmatched(ss.remote.String())
		if !s.conns.acquire(key, unmatchedMaxConns) {
			ss.reply(421, "4.7.0 too many connections")
			return
		}
		defer s.conns.release(key, unmatchedMaxConns)
		ss.deadline = time.Now().Add(unmatchedMaxSession)
	}

	ss.reply(220, s.cfg.Service.Hostname+" ESMTP smtprelayd")
	ss.loop()
}

// loop reads and dispatches commands until the session ends. The context is
// s.ctx, set by handle; it is not a parameter because the session already
// carries it and two spellings of the same value is one more than can be
// right.
func (s *session) loop() {
	for {
		if s.writeFailed {
			// Nothing can be said about it: saying it is what just failed.
			return
		}
		if !s.deadline.IsZero() && !time.Now().Before(s.deadline) {
			s.reply(421, "4.7.0 session time limit reached")
			return
		}
		// The shutdown check comes after the deadline is armed, not before:
		// see armRead for why the order matters.
		s.armRead(s.readDeadline(s.srv.cfg.Limits.ReadTimeoutSec))
		if s.ctx.Err() != nil {
			s.reply(421, "4.3.2 service shutting down")
			return
		}
		line, err := readStructuredLine(s.br, maxLineOctet)
		if err != nil {
			if errors.Is(err, errLineTooLong) || errors.Is(err, errNulByte) || errors.Is(err, errBareCR) {
				s.reply(500, "5.5.2 "+err.Error())
			}
			return
		}

		verb, arg := splitCommand(line)
		switch verb {
		case "EHLO", "HELO":
			s.doHelo(verb, arg)
		case "STARTTLS":
			if !s.doStartTLS() {
				return
			}
		case "MAIL":
			s.doMail(arg)
		case "RCPT":
			s.doRcpt(arg)
		case "DATA":
			if !s.doData() {
				return
			}
		case "RSET":
			s.resetTransaction()
			s.reply(250, "2.0.0 OK")
		case "NOOP":
			s.reply(250, "2.0.0 OK")
		case "VRFY", "EXPN":
			// Never confirm whether an address exists.
			s.reply(252, "2.5.2 cannot verify")
		case "QUIT":
			s.reply(221, "2.0.0 bye")
			return
		case "AUTH":
			// Inbound authentication is not offered: clients are authorised by
			// source address. Advertising it would invite credential guessing.
			s.reply(502, "5.5.1 command not implemented")
		default:
			s.reply(500, "5.5.1 command not recognised")
		}
	}
}

func (s *session) doHelo(verb, arg string) {
	arg = strings.TrimSpace(arg)
	if arg == "" || len(arg) > 255 || strings.ContainsAny(arg, "\r\n\x00") {
		s.reply(501, "5.5.4 invalid argument")
		return
	}
	s.helo = arg
	s.resetTransaction()

	if verb == "HELO" {
		s.reply(250, s.srv.cfg.Service.Hostname)
		return
	}

	ext := []string{
		s.srv.cfg.Service.Hostname,
		"SIZE " + strconv.FormatInt(s.maxMessageBytes(), 10),
		"8BITMIME",
		"PIPELINING",
		"ENHANCEDSTATUSCODES",
	}
	if s.srv.lc.TLS == config.TLSStartTLS && !s.isTLS {
		ext = append(ext, "STARTTLS")
	}
	s.multiline(250, ext)
}

func (s *session) doStartTLS() bool {
	if s.srv.lc.TLS != config.TLSStartTLS || s.srv.tlsConf == nil {
		s.reply(502, "5.5.1 command not implemented")
		return true
	}
	if s.isTLS {
		s.reply(503, "5.5.1 TLS already active")
		return true
	}
	s.reply(220, "2.0.0 ready to start TLS")

	tc := tls.Server(s.conn, s.srv.tlsConf)
	_ = tc.SetDeadline(s.readDeadline(s.srv.cfg.Limits.ReadTimeoutSec))
	if s.ctx.Err() != nil {
		// Same race armRead closes: the deadline just set may have
		// overwritten the expired one the shutdown hook installed.
		_ = tc.SetDeadline(time.Now())
	}
	if err := tc.HandshakeContext(s.ctx); err != nil {
		s.log.Debug("starttls handshake failed", "error", err)
		return false
	}
	s.conn = tc
	s.br = bufio.NewReaderSize(tc, 4096)
	s.bw = bufio.NewWriter(tc)
	s.isTLS = true
	// RFC 3207: everything learned before the handshake is discarded.
	s.helo = ""
	s.resetTransaction()
	return true
}

func (s *session) doMail(arg string) {
	if s.client == nil {
		s.log.Warn("relay denied for unmatched source")
		s.reply(550, "5.7.1 relay access denied")
		return
	}
	if s.helo == "" {
		s.reply(503, "5.5.1 send HELO or EHLO first")
		return
	}
	if s.srv.lc.RequireTLS && !s.isTLS {
		s.reply(530, "5.7.0 must issue a STARTTLS command first")
		return
	}
	if s.fromSet {
		s.reply(503, "5.5.1 nested MAIL command")
		return
	}
	upper := strings.ToUpper(arg)
	if !strings.HasPrefix(upper, "FROM:") {
		s.reply(501, "5.5.4 expected MAIL FROM:<address>")
		return
	}
	addr, params, err := parsePath(arg[len("FROM:"):])
	if err != nil {
		s.reply(501, "5.1.7 "+err.Error())
		return
	}
	if !s.checkSizeParam(params) {
		return
	}
	if !s.srv.rate.allow(s.client.Name, s.client.RateLimitPerMin, time.Now()) {
		s.log.Warn("client rate limit exceeded", "limit_per_min", s.client.RateLimitPerMin)
		s.reply(451, "4.7.0 rate limit exceeded, try again later")
		return
	}

	s.from = addr
	s.fromSet = true
	s.reply(250, "2.1.0 OK")
}

// checkSizeParam enforces the announced SIZE against this session's ceiling,
// replying itself and reporting false when the transaction must not continue.
// Refusing here costs the client one command instead of a whole transfer.
func (s *session) checkSizeParam(params []string) bool {
	for _, p := range params {
		if !strings.HasPrefix(strings.ToUpper(p), "SIZE=") {
			continue
		}
		n, err := strconv.ParseInt(p[len("SIZE="):], 10, 64)
		if err != nil {
			s.reply(501, "5.5.4 invalid SIZE parameter")
			return false
		}
		if n > s.maxMessageBytes() {
			s.reply(552, "5.3.4 message exceeds size limit")
			return false
		}
	}
	return true
}

func (s *session) doRcpt(arg string) {
	if !s.fromSet {
		s.reply(503, "5.5.1 send MAIL FROM first")
		return
	}
	// After the fromSet check, never before it: an unmatched source is
	// refused at MAIL FROM so that the reply names the actual reason, and
	// checking the client first would move that refusal a command earlier.
	//
	// fromSet is only ever set by doMail, which refuses an unmatched source,
	// so a nil client cannot get past the line above today. That is an
	// invariant held at a distance of forty lines, and what it holds back is
	// a nil dereference in the command path of a default-deny listener --
	// recovered by the session guard, but as a counted panic and a dropped
	// connection. Stated where it is relied on, it costs one comparison.
	if s.client == nil {
		s.reply(503, "5.5.1 send MAIL FROM first")
		return
	}
	max := s.client.MaxRecipients
	if max <= 0 {
		max = defaultMaxRecipients
	}
	if len(s.rcpts) >= max {
		s.reply(452, "4.5.3 too many recipients")
		return
	}
	upper := strings.ToUpper(arg)
	if !strings.HasPrefix(upper, "TO:") {
		s.reply(501, "5.5.4 expected RCPT TO:<address>")
		return
	}
	addr, _, err := parsePath(arg[len("TO:"):])
	if err != nil {
		s.reply(501, "5.1.3 "+err.Error())
		return
	}
	if addr == "" {
		s.reply(501, "5.1.3 empty recipient")
		return
	}
	s.rcpts = append(s.rcpts, addr)
	s.reply(250, "2.1.5 OK")
}

// doData streams the message into the spool. It returns false when the
// connection must be closed, which is the case for any error inside the data
// phase: once the stream is abandoned the command channel is out of sync.
func (s *session) doData() bool {
	if !s.fromSet || len(s.rcpts) == 0 {
		s.reply(503, "5.5.1 send MAIL FROM and RCPT TO first")
		return true
	}
	// Routing is resolved before 354 so that a configuration fault costs the
	// client a command instead of a whole message transfer.
	groups, err := s.srv.router.Split(s.rcpts, s.remote, s.client.Route, s.clientBits)
	if err != nil {
		s.log.Error("no route for recipient", "error", err)
		s.reply(451, "4.3.5 no route configured")
		return true
	}

	s.reply(354, "end data with <CR><LF>.<CR><LF>")
	s.armRead(s.readDeadline(s.srv.cfg.Limits.DataTimeoutSec))

	dr := newDotReader(s.br)
	hr := bufio.NewReader(dr)
	staged, res, ok := s.stageMessage(hr)
	if !ok {
		return false
	}
	defer staged.Discard()

	lifetime := time.Duration(s.srv.cfg.Queue.MaxLifetimeHours) * time.Hour
	ids, ok := s.commitCopies(staged, res, groups, lifetime)
	if !ok {
		return false
	}

	s.reply(250, "2.0.0 OK queued as "+strings.Join(ids, " "))
	s.resetTransaction()

	// End of data on anything other than <CRLF>.<CRLF>. The message is
	// acknowledged -- it is queued and a legacy device must not be told
	// otherwise -- but the stream is not handed back to the command loop,
	// because whatever follows the dot was chosen by whoever wrote the body.
	if dr.smuggled {
		s.log.Warn("data ended on a bare LF dot line, closing the session",
			"queue_ids", strings.Join(ids, " "))
		return false
	}
	return true
}

// stageMessage reads the message body, applies the client's rewriting rules
// and stages one copy of the result. It replies to the client itself on every
// failure, so a false return means the session is finished with this message.
// The caller owns the returned stage and must Discard it.
func (s *session) stageMessage(hr *bufio.Reader) (*spool.Staged, rewrite.Result, bool) {
	headers, hops, err := scanHeaders(hr, s.srv.cfg.Limits)
	if err != nil {
		s.replyDataError(err)
		return nil, rewrite.Result{}, false
	}
	if hops >= s.srv.cfg.Limits.MaxHops {
		s.log.Warn("hop count exceeded", "hops", hops)
		s.reply(554, "5.4.6 too many hops, routing loop suspected")
		return nil, rewrite.Result{}, false
	}

	res, err := s.srv.rules[s.client.Name].Apply(rewrite.Input{
		EnvelopeFrom: s.from,
		Headers:      headers,
	})
	if err != nil {
		// The message cannot be rewritten without guessing at a header the
		// client supplied. Rejecting permanently is the only honest answer.
		s.log.Warn("sender rewriting refused the message", "error", err)
		s.reply(550, "5.6.0 message headers cannot be rewritten safely")
		return nil, rewrite.Result{}, false
	}

	staged, err := s.srv.spool.Stage(
		io.MultiReader(strings.NewReader(res.Headers), hr), s.maxMessageBytes())
	if err != nil {
		s.replyDataError(err)
		return nil, rewrite.Result{}, false
	}
	return staged, res, true
}

// commitCopies makes one queued copy per route group. A partial accept would
// be delivered once and again when the client retries, so a failure withdraws
// the copies already made before replying. It replies to the client itself on
// failure; a false return means the session is finished with this message.
func (s *session) commitCopies(staged *spool.Staged, res rewrite.Result, groups []router.Group, lifetime time.Duration) ([]string, bool) {
	committed := make([]spool.ID, 0, len(groups))
	ids := make([]string, 0, len(groups))

	// Once, not once per group: the header block is the same for every copy,
	// and reading these four values costs a parse each. See journalMeta.
	meta := s.journalMetaOf(res.Headers)

	for _, g := range groups {
		env := spool.Envelope{
			From:         res.EnvelopeFrom,
			To:           append([]string(nil), g.Recipients...),
			OriginalFrom: res.OriginalFrom,
			Client:       s.client.Name,
			Route:        g.Route,
			Listener:     s.srv.lc.Name,
			RemoteAddr:   s.remote.String(),
			Helo:         s.helo,
			TLS:          s.isTLS,
			Received:     time.Now().UTC(),
		}
		id, err := s.srv.spool.Commit(staged, env, lifetime, s.receivedHeader)
		if err != nil {
			s.withdraw(committed)
			s.log.Error("enqueue failed", "route", g.Route, "error", err)
			s.replyDataError(err)
			return nil, false
		}
		committed = append(committed, id)
		ids = append(ids, id.String())

		s.journalAccepted(id, g, res, meta, env.Received, staged.Size(), lifetime)

		s.log.Info("message accepted",
			"queue_id", id.String(), "from", res.EnvelopeFrom,
			"original_from", res.OriginalFrom, "rewritten", res.Rewritten,
			"recipients", len(g.Recipients), "route", g.Route, "route_reason", g.Reason,
			"message_id", meta.messageID, "size_bytes", staged.Size())
	}

	return ids, true
}

// withdraw un-queues the copies made before a later one failed. A partial
// accept would be delivered once and then again when the client retries the
// whole message, so nothing may stay queued for a transaction the client is
// about to be told was not accepted.
func (s *session) withdraw(committed []spool.ID) {
	for _, done := range committed {
		if err := s.srv.spool.Remove(done); err != nil {
			s.log.Error("could not withdraw a partially queued copy",
				"queue_id", done.String(), "error", err)
		}
	}
}

func (s *session) replyDataError(err error) {
	switch {
	case errors.Is(err, spool.ErrTooLarge):
		s.reply(552, "5.3.4 message exceeds size limit")
	case errors.Is(err, errLineTooLong):
		s.reply(500, "5.5.2 line exceeds 1000 octets")
	case errors.Is(err, errNulByte):
		s.reply(500, "5.5.2 NUL byte in message")
	case errors.Is(err, errBareCR):
		s.reply(500, "5.5.2 bare CR in message headers")
	case errors.Is(err, errTooManyHdrs), errors.Is(err, errHdrTooLarge):
		s.reply(552, "5.3.4 "+err.Error())
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		// The peer vanished mid-transfer; nothing useful to say.
	default:
		s.log.Error("data phase failed", "error", err)
		s.reply(451, "4.3.0 error accepting message")
	}
}

// receivedHeader records the hop. Every value interpolated here has already
// been rejected if it contained CR, LF or NUL — the three that can end a line
// — so the header cannot be split by client input. That is narrower than "no
// control characters": a HELO name may still contain, say, a BEL, which is
// ugly in a header but cannot split one. The comment claimed the broader
// property until 2026-08-11.
func (s *session) receivedHeader(id spool.ID) string {
	proto := "SMTP"
	if s.isTLS {
		proto = "ESMTPS"
	} else if s.helo != "" {
		proto = "ESMTP"
	}
	return fmt.Sprintf("Received: from %s (%s)\r\n\tby %s with %s id %s;\r\n\t%s\r\n",
		s.helo, s.remote.String(), s.srv.cfg.Service.Hostname, proto, id.String(),
		time.Now().Format(time.RFC1123Z))
}

// maxMessageBytes is the global limit unless the client narrows it. A client
// can only lower the limit: the loader rejects a client value above the
// global one, so no client can raise the ceiling for itself.
func (s *session) maxMessageBytes() int64 {
	mb := s.srv.cfg.Limits.MaxMessageMB
	if mb <= 0 {
		mb = defaultMaxMessageMB
	}
	if s.client != nil && s.client.MaxMessageMB > 0 && s.client.MaxMessageMB < mb {
		mb = s.client.MaxMessageMB
	}
	return int64(mb) * 1024 * 1024
}

// armRead sets the read deadline for the next command or the data phase.
//
// handle installs a hook that expires the deadline when ctx is cancelled, so
// that a session blocked in a read ends at once on shutdown. That hook and
// this call race: a cancellation landing between the loop's shutdown check
// and the SetReadDeadline here was overwritten by it, and the session then
// sat in the read for the full read_timeout_sec -- or data_timeout_sec, five
// minutes by default -- while Set.Close waited on it and the Windows SCM
// counted down its stop timeout. Re-checking after arming closes the window:
// the hook has either already fired, in which case the deadline is expired
// again here, or has not, in which case it will fire against the deadline
// just set.
func (s *session) armRead(t time.Time) {
	_ = s.conn.SetReadDeadline(t)
	if s.ctx != nil && s.ctx.Err() != nil {
		_ = s.conn.SetReadDeadline(time.Now())
	}
}

// readDeadline is the per-command deadline, clamped to the session deadline so
// that a source which simply stops sending cannot outlive its session budget
// inside a single blocking read.
func (s *session) readDeadline(sec int) time.Time {
	d := time.Now().Add(s.timeout(sec))
	if !s.deadline.IsZero() && s.deadline.Before(d) {
		return s.deadline
	}
	return d
}

func (s *session) timeout(sec int) time.Duration {
	if sec <= 0 {
		sec = defaultTimeoutSec
	}
	return time.Duration(sec) * time.Second
}

func (s *session) resetTransaction() {
	s.from = ""
	s.fromSet = false
	s.rcpts = nil
}

// reply writes one reply line. A write that fails is recorded rather than
// returned: every caller answers the client and then either returns or falls
// back to the command loop, which checks writeFailed and ends the session.
// Before that the loop kept reading from a peer that had already gone, for
// the whole read_timeout_sec, holding a connection slot the whole time.
func (s *session) reply(code int, msg string) {
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.timeout(s.srv.cfg.Limits.WriteTimeoutSec)))
	fmt.Fprintf(s.bw, "%d %s\r\n", code, msg)
	s.flush()
}

func (s *session) multiline(code int, lines []string) {
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.timeout(s.srv.cfg.Limits.WriteTimeoutSec)))
	for i, l := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		fmt.Fprintf(s.bw, "%d%s%s\r\n", code, sep, l)
	}
	s.flush()
}

func (s *session) flush() {
	if err := s.bw.Flush(); err != nil {
		s.writeFailed = true
		s.log.Debug("writing a reply failed, ending the session", "error", err)
	}
}
