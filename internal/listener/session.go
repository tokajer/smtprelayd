// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/rewrite"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

const defaultMaxMessageMB = 50

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

var (
	errLineTooLong = errors.New("line exceeds 1000 octets")
	errNulByte     = errors.New("NUL byte in input")
	errBareCR      = errors.New("bare CR in input")
	errTooManyHdrs = errors.New("too many headers")
	errHdrTooLarge = errors.New("header block too large")
)

type session struct {
	srv  *Server
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
	declared int64
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()

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
		if !s.conns.acquire(client.Name, client.MaxConnections) {
			ss.reply(421, "4.7.0 too many connections for this client")
			return
		}
		defer s.conns.release(client.Name, client.MaxConnections)
		ss.client = client
		ss.clientBits = bits
		ss.log = ss.log.With("client", client.Name)
	} else {
		// The refusal itself still happens at MAIL FROM, so that the reply
		// names the actual reason. What changes here is only how much of the
		// server an unauthorised source may occupy while getting there.
		key := "unmatched:" + ss.remote.String()
		if !s.conns.acquire(key, unmatchedMaxConns) {
			ss.reply(421, "4.7.0 too many connections")
			return
		}
		defer s.conns.release(key, unmatchedMaxConns)
		ss.deadline = time.Now().Add(unmatchedMaxSession)
	}

	ss.reply(220, s.cfg.Service.Hostname+" ESMTP smtprelayd")
	ss.loop(ctx)
}

func (s *session) loop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			s.reply(421, "4.3.2 service shutting down")
			return
		}
		if !s.deadline.IsZero() && !time.Now().Before(s.deadline) {
			s.reply(421, "4.7.0 session time limit reached")
			return
		}
		_ = s.conn.SetReadDeadline(s.readDeadline(s.srv.cfg.Limits.ReadTimeoutSec))
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
			if !s.doStartTLS(ctx) {
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
	if s.srv.lc.TLS == "starttls" && !s.isTLS {
		ext = append(ext, "STARTTLS")
	}
	s.multiline(250, ext)
}

func (s *session) doStartTLS(ctx context.Context) bool {
	if s.srv.lc.TLS != "starttls" || s.srv.tlsConf == nil {
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
	if err := tc.HandshakeContext(ctx); err != nil {
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
	for _, p := range params {
		if strings.HasPrefix(strings.ToUpper(p), "SIZE=") {
			n, err := strconv.ParseInt(p[5:], 10, 64)
			if err != nil {
				s.reply(501, "5.5.4 invalid SIZE parameter")
				return
			}
			if n > s.maxMessageBytes() {
				s.reply(552, "5.3.4 message exceeds size limit")
				return
			}
			s.declared = n
		}
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

func (s *session) doRcpt(arg string) {
	if !s.fromSet {
		s.reply(503, "5.5.1 send MAIL FROM first")
		return
	}
	max := s.client.MaxRecipients
	if max <= 0 {
		max = 100
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
	_ = s.conn.SetReadDeadline(s.readDeadline(s.srv.cfg.Limits.DataTimeoutSec))

	if s.declared > 0 && s.declared > s.maxMessageBytes() {
		s.reply(552, "5.3.4 message exceeds size limit")
		return false
	}

	dr := newDotReader(s.br)
	hr := bufio.NewReader(dr)
	headers, hops, err := scanHeaders(hr, s.srv.cfg.Limits)
	if err != nil {
		s.replyDataError(err)
		return false
	}
	if hops >= s.srv.cfg.Limits.MaxHops {
		s.log.Warn("hop count exceeded", "hops", hops)
		s.reply(554, "5.4.6 too many hops, routing loop suspected")
		return false
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
		return false
	}

	staged, err := s.srv.spool.Stage(
		io.MultiReader(strings.NewReader(res.Headers), hr), s.maxMessageBytes())
	if err != nil {
		s.replyDataError(err)
		return false
	}
	defer staged.Discard()

	lifetime := time.Duration(s.srv.cfg.Queue.MaxLifetimeHours) * time.Hour
	committed := make([]spool.ID, 0, len(groups))
	ids := make([]string, 0, len(groups))

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
			// A partial accept would be delivered once and then again when
			// the client retries, so the copies already made are withdrawn.
			for _, done := range committed {
				if rmErr := s.srv.spool.Remove(done); rmErr != nil {
					s.log.Error("could not withdraw a partially queued copy",
						"queue_id", done.String(), "error", rmErr)
				}
			}
			s.log.Error("enqueue failed", "route", g.Route, "error", err)
			s.replyDataError(err)
			return false
		}
		committed = append(committed, id)
		ids = append(ids, id.String())

		// Record message in history store. Subject is stored only if
		// retain_subjects is enabled; store.RecordMessage redacts it again
		// regardless, this just avoids parsing the header block for nothing.
		recipientsJSON, _ := json.Marshal(g.Recipients)
		subject := ""
		if s.srv.cfg.History.RetainSubjects {
			subject = sanitizeSubject(rewrite.HeaderValue(res.Headers, "Subject"))
		}
		// Journal metadata describes what was spooled, so it is read from
		// the rewritten header block and the staged size rather than from
		// the headers the client sent or the size it announced.
		messageID := sanitizeHeaderMeta(rewrite.HeaderValue(res.Headers, "Message-ID"), maxStoredMessageID)
		contentType := sanitizeHeaderMeta(rewrite.HeaderValue(res.Headers, "Content-Type"), maxStoredContentType)
		_ = s.srv.store.RecordMessage(store.MessageRecord{
			QueueID:      id.String(),
			Client:       s.client.Name,
			Route:        g.Route,
			EnvelopeFrom: res.EnvelopeFrom,
			OriginalFrom: res.OriginalFrom,
			Recipients:   string(recipientsJSON),
			Subject:      subject,
			Listener:     s.srv.lc.Name,
			RemoteAddr:   s.remote.String(),
			MessageID:    messageID,
			ContentType:  contentType,
			SizeBytes:    staged.Size(),
			HeaderCount:  rewrite.HeaderCount(res.Headers),
			Helo:         sanitizeHeaderMeta(s.helo, maxStoredHelo),
			ReceivedAt:   env.Received,
			ExpiresAt:    env.Received.Add(lifetime),
			TLSUsed:      s.isTLS,
		})

		s.log.Info("message accepted",
			"queue_id", id.String(), "from", res.EnvelopeFrom,
			"original_from", res.OriginalFrom, "rewritten", res.Rewritten,
			"recipients", len(g.Recipients), "route", g.Route, "route_reason", g.Reason,
			"message_id", messageID, "size_bytes", staged.Size())
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

// Bounds on the header values kept in the history store. These are display
// and journal metadata, not protocol values, so they are generous headroom
// rather than protocol limits.
const (
	maxStoredSubject     = 500
	maxStoredMessageID   = 200
	maxStoredContentType = 200
	maxStoredHelo        = 255 // the protocol limit doHelo already enforces
)

// sanitizeHeaderMeta strips control characters from a header value before it
// enters the history store and bounds its length. This is metadata for
// display, not a header that gets written back onto the wire, so stripping is
// the right response to a stray control character rather than rejecting the
// whole message the way the rewrite package does for From.
func sanitizeHeaderMeta(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		// Cut on a rune boundary: a stored half rune would render as a
		// replacement character everywhere it is displayed.
		for max > 0 && !utf8.RuneStart(s[max]) {
			max--
		}
		s = s[:max]
	}
	return s
}

func sanitizeSubject(s string) string {
	return sanitizeHeaderMeta(s, maxStoredSubject)
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
		sec = 60
	}
	return time.Duration(sec) * time.Second
}

func (s *session) resetTransaction() {
	s.from = ""
	s.fromSet = false
	s.rcpts = nil
	s.declared = 0
}

func (s *session) reply(code int, msg string) {
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.timeout(s.srv.cfg.Limits.WriteTimeoutSec)))
	fmt.Fprintf(s.bw, "%d %s\r\n", code, msg)
	_ = s.bw.Flush()
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
	_ = s.bw.Flush()
}

func splitCommand(line string) (verb, arg string) {
	line = strings.TrimLeft(line, " \t")
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		return strings.ToUpper(line[:i]), line[i+1:]
	}
	return strings.ToUpper(line), ""
}

// readLineLimited reads one line, refusing to buffer more than max octets so
// that a client cannot exhaust memory with one long line. A bare LF is
// accepted as a terminator because legacy devices emit them, but crlf reports
// which terminator was actually seen: the end-of-data dot is the one place
// where the difference decides whether the remainder of the stream is a
// message body or an SMTP command, so that distinction must survive this far.
func readLineLimited(br *bufio.Reader, max int) (line string, crlf bool, err error) {
	var sb strings.Builder
	for {
		chunk, err := br.ReadSlice('\n')
		if sb.Len()+len(chunk) > max {
			return "", false, errLineTooLong
		}
		sb.Write(chunk)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return "", false, err
		}
		break
	}
	s := strings.TrimSuffix(sb.String(), "\n")
	if strings.HasSuffix(s, "\r") {
		s, crlf = strings.TrimSuffix(s, "\r"), true
	}
	if strings.IndexByte(s, 0) >= 0 {
		return "", false, errNulByte
	}
	return s, crlf, nil
}

// readStructuredLine reads a line that will be interpreted rather than
// carried: an SMTP command, or a header line that is re-emitted into the
// spooled message. A CR inside such a line is rejected, because the next
// parser in the chain decides on its own whether that CR ends a line, and
// that disagreement is what header injection is made of. Rejected rather
// than stripped, per the rule that CR, LF and NUL fail a message instead of
// being sanitised.
//
// The body deliberately does not go through here. A lone CR in a message
// body is not a header and cannot split one; a legacy device that emits one
// would lose the whole message for a byte that only ever reaches the
// smarthost as content.
func readStructuredLine(br *bufio.Reader, max int) (string, error) {
	s, _, err := readLineLimited(br, max)
	if err != nil {
		return "", err
	}
	if strings.IndexByte(s, '\r') >= 0 {
		return "", errBareCR
	}
	return s, nil
}

// dotReader yields the message body with transparency dots removed and the
// 1000 octet line limit enforced.
//
// RFC 5321 ends DATA on <CRLF>.<CRLF>, and only that sequence may hand the
// stream back to the command loop. Accepting a bare <LF>.<LF> there turns
// "controls the message body" into "controls the envelope": whatever follows
// the dot is executed as SMTP commands, so a contact form or an ERP system on
// an allowlisted host could inject its own MAIL FROM and RCPT TO. Checking
// only the dot line's own terminator is not enough — <LF>.<CRLF> smuggles
// just as well — so the preceding line's terminator is tracked too.
//
// Legacy devices that speak bare LF throughout are exactly this relay's
// users, so their end-of-data is still honoured rather than left to time out.
// It sets smuggled instead, and the caller closes the session after
// acknowledging the message: the message is delivered, the injection is not.
type dotReader struct {
	br   *bufio.Reader
	rest []byte
	done bool

	// prevCRLF is the previous body line's terminator. It starts true so that
	// an empty message (the dot as the very first line) is judged on the dot
	// line alone; the DATA command that opened the phase is not a body line.
	prevCRLF bool
	smuggled bool
}

func newDotReader(br *bufio.Reader) *dotReader {
	return &dotReader{br: br, prevCRLF: true}
}

func (d *dotReader) Read(p []byte) (int, error) {
	for len(d.rest) == 0 {
		if d.done {
			return 0, io.EOF
		}
		line, crlf, err := readLineLimited(d.br, maxLineOctet)
		if err != nil {
			d.done = true
			return 0, err
		}
		if line == "." {
			d.done = true
			d.smuggled = !crlf || !d.prevCRLF
			return 0, io.EOF
		}
		d.prevCRLF = crlf
		if strings.HasPrefix(line, ".") {
			line = line[1:]
		}
		d.rest = []byte(line + "\r\n")
	}
	n := copy(p, d.rest)
	d.rest = d.rest[n:]
	return n, nil
}

// scanHeaders reads the header block, enforces the parser limits, counts
// existing Received headers for loop detection and drops headers that would
// misrepresent the message origin.
func scanHeaders(br *bufio.Reader, lim config.Limits) (headers string, received int, err error) {
	var sb strings.Builder
	count, size := 0, 0
	dropping := false

	for {
		line, err := readStructuredLine(br, maxLineOctet)
		if err != nil {
			if errors.Is(err, io.EOF) {
				// A message consisting of headers only and no blank line.
				return sb.String(), received, nil
			}
			return "", 0, err
		}
		size += len(line) + 2
		if size > lim.MaxHeaderBytes {
			return "", 0, errHdrTooLarge
		}
		if line == "" {
			sb.WriteString("\r\n")
			return sb.String(), received, nil
		}

		folded := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
		if !folded {
			count++
			if count > lim.MaxHeaders {
				return "", 0, errTooManyHdrs
			}
			name := line
			if i := strings.IndexByte(line, ':'); i >= 0 {
				name = line[:i]
			}
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "received":
				received++
				dropping = false
			case "return-path", "x-original-from":
				// Supplied by the client these are pure misdirection; the
				// relay owns both.
				dropping = true
			default:
				dropping = false
			}
		}
		if dropping {
			continue
		}
		sb.WriteString(line)
		sb.WriteString("\r\n")
	}
}
