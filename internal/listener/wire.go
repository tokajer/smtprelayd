// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"bufio"
	"errors"
	"io"
	"strings"

	"github.com/tokajer/smtprelayd/internal/config"
)

// The SMTP wire format: how a command line, a header block and the DATA
// stream are read off the socket and turned into values the session can act
// on. Nothing here touches a session, a spool or a configuration beyond the
// parser limits it is handed.
//
// It is the highest-risk code in the listener -- every rule about CR, LF and
// NUL that keeps a client from splitting a header line downstream is in this
// file -- which is why it is a file a reviewer can open on its own rather
// than 180 lines in the middle of the command loop.

var (
	errLineTooLong = errors.New("line exceeds 1000 octets")
	errNulByte     = errors.New("NUL byte in input")
	errBareCR      = errors.New("bare CR in input")
	errTooManyHdrs = errors.New("too many headers")
	errHdrTooLarge = errors.New("header block too large")
)

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
		// Undo dot-stuffing: exactly one leading dot, per RFC 5321 4.5.2.
		d.rest = []byte(strings.TrimPrefix(line, ".") + "\r\n")
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
