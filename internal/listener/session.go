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
	"github.com/tokajer/smtprelayd/internal/spool"
)

const defaultMaxMessageMB = 50

var (
	errLineTooLong = errors.New("line exceeds 1000 octets")
	errNulByte     = errors.New("NUL byte in input")
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
	isTLS      bool
	helo       string
	from       string
	fromSet    bool
	rcpts      []string
	declared   int64
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
		_ = s.conn.SetReadDeadline(time.Now().Add(s.timeout(s.srv.cfg.Limits.ReadTimeoutSec)))
		line, err := readLineLimited(s.br, maxLineOctet)
		if err != nil {
			if errors.Is(err, errLineTooLong) || errors.Is(err, errNulByte) {
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
	_ = tc.SetDeadline(time.Now().Add(s.timeout(s.srv.cfg.Limits.ReadTimeoutSec)))
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
	_ = s.conn.SetReadDeadline(time.Now().Add(s.timeout(s.srv.cfg.Limits.DataTimeoutSec)))

	dr := &dotReader{br: s.br}
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
		s.log.Info("message accepted",
			"queue_id", id.String(), "from", res.EnvelopeFrom,
			"original_from", res.OriginalFrom, "rewritten", res.Rewritten,
			"recipients", len(g.Recipients), "route", g.Route, "route_reason", g.Reason)
	}

	s.reply(250, "2.0.0 OK queued as "+strings.Join(ids, " "))
	s.resetTransaction()
	return true
}

func (s *session) replyDataError(err error) {
	switch {
	case errors.Is(err, spool.ErrTooLarge):
		s.reply(552, "5.3.4 message exceeds size limit")
	case errors.Is(err, errLineTooLong):
		s.reply(500, "5.5.2 line exceeds 1000 octets")
	case errors.Is(err, errNulByte):
		s.reply(500, "5.5.2 NUL byte in message")
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
// been rejected if it contained a control character, so the header cannot be
// split by client input.
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

// readLineLimited reads one CRLF-terminated line, refusing to buffer more
// than max octets so that a client cannot exhaust memory with one long line.
func readLineLimited(br *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for {
		chunk, err := br.ReadSlice('\n')
		if sb.Len()+len(chunk) > max {
			return "", errLineTooLong
		}
		sb.Write(chunk)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return "", err
		}
		break
	}
	s := strings.TrimSuffix(strings.TrimSuffix(sb.String(), "\n"), "\r")
	if strings.IndexByte(s, 0) >= 0 {
		return "", errNulByte
	}
	return s, nil
}

// dotReader yields the message body with transparency dots removed and the
// 1000 octet line limit enforced.
type dotReader struct {
	br   *bufio.Reader
	rest []byte
	done bool
}

func (d *dotReader) Read(p []byte) (int, error) {
	for len(d.rest) == 0 {
		if d.done {
			return 0, io.EOF
		}
		line, err := readLineLimited(d.br, maxLineOctet)
		if err != nil {
			d.done = true
			return 0, err
		}
		if line == "." {
			d.done = true
			return 0, io.EOF
		}
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
		line, err := readLineLimited(br, maxLineOctet)
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
