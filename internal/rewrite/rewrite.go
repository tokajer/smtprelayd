// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package rewrite applies per-client sender rewriting rules.
//
// This is the highest-risk code in the relay: it writes client-influenced
// values into message headers. Two rules hold everywhere in this package.
// First, every value that reaches a header is either a validated
// configuration value or is checked here, and a value that fails its check
// causes rejection rather than sanitisation. Second, headers are replaced
// structurally through the block type, never by string concatenation against
// the raw block.
//
// The message body is never parsed or touched, so no MIME structure can be
// corrupted by rewriting.
package rewrite

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tokajer/smtprelayd/internal/config"
)

// Rewrite modes, mirroring config.Rewrite.Mode.
const (
	ModeOff            = "off"
	ModeIfUnauthorized = "if_unauthorized"
	ModeForce          = "force"

	// HeaderFromKeep leaves the client's From header in place, provided it is
	// aligned with the rewritten envelope sender. A misaligned From is
	// replaced anyway, because SPF checks the envelope and DMARC the header:
	// keeping a foreign From would produce a message the smarthost rejects.
	HeaderFromKeep = "keep"
)

// Reply-To dispositions.
const (
	replyPreserve = "preserve"
	replyDrop     = "drop"
	replyFixed    = "fixed"
)

var (
	// ErrAmbiguousFrom is returned when the message carries more than one
	// From header. Which one a downstream agent honours is not defined, so
	// rewriting one of them would be a guess.
	ErrAmbiguousFrom = errors.New("rewrite: message carries more than one From header")

	// ErrUnsafeHeader is returned when a value that would be preserved
	// contains a control character.
	ErrUnsafeHeader = errors.New("rewrite: header value contains a control character")

	// ErrHeaderTooLong is returned when the original From is too long to be
	// preserved on a single line.
	ErrHeaderTooLong = errors.New("rewrite: From header is too long to preserve")
)

// maxPreservedFrom bounds what may be copied into X-Original-From. With the
// header name this stays well inside the 998 octet line limit.
const maxPreservedFrom = 512

// Rules is the compiled rewrite policy of one client.
type Rules struct {
	mode       string
	allowed    []pattern
	envFrom    string
	headerFrom string // "", HeaderFromKeep, or a formatted mailbox
	replyTo    string
	replyFixed string
}

// pattern is one allowed_senders entry. An empty local part means *@domain.
type pattern struct {
	local  string
	domain string
}

// Compile turns a client's rewrite block into an applier. It repeats the
// checks the loader already made: this package is the last place before a
// value reaches a header, and it must not depend on having been called with
// a validated configuration.
func Compile(r config.Rewrite) (*Rules, error) {
	out := &Rules{
		mode:       r.Mode,
		envFrom:    strings.TrimSpace(r.EnvelopeFrom),
		headerFrom: strings.TrimSpace(r.HeaderFrom),
	}
	if out.mode == "" {
		out.mode = ModeOff
	}
	switch out.mode {
	case ModeOff:
		return out, nil
	case ModeIfUnauthorized, ModeForce:
	default:
		return nil, fmt.Errorf("rewrite: unknown mode %q", r.Mode)
	}

	if !config.ValidAddress(out.envFrom) {
		return nil, fmt.Errorf("rewrite: envelope_from %q is not a valid address", r.EnvelopeFrom)
	}
	if out.headerFrom != "" && out.headerFrom != HeaderFromKeep {
		display, addr, ok := config.SplitMailbox(out.headerFrom)
		if !ok {
			return nil, fmt.Errorf("rewrite: header_from %q is not a valid mailbox", r.HeaderFrom)
		}
		if config.DomainOf(addr) != config.DomainOf(out.envFrom) {
			return nil, fmt.Errorf("rewrite: header_from domain %q does not match envelope_from domain %q",
				config.DomainOf(addr), config.DomainOf(out.envFrom))
		}
		out.headerFrom = formatMailbox(display, addr)
	}
	for _, s := range r.AllowedSenders {
		p, err := compilePattern(s)
		if err != nil {
			return nil, err
		}
		out.allowed = append(out.allowed, p)
	}
	if out.mode == ModeIfUnauthorized && len(out.allowed) == 0 {
		return nil, errors.New("rewrite: mode if_unauthorized requires allowed_senders")
	}

	switch rt := strings.TrimSpace(r.ReplyTo); {
	case rt == "" || rt == replyPreserve:
		out.replyTo = replyPreserve
	case rt == replyDrop:
		out.replyTo = replyDrop
	case strings.HasPrefix(rt, "fixed:"):
		addr := strings.TrimSpace(strings.TrimPrefix(rt, "fixed:"))
		if !config.ValidAddress(addr) {
			return nil, fmt.Errorf("rewrite: reply_to fixed address %q is not valid", addr)
		}
		out.replyTo, out.replyFixed = replyFixed, addr
	default:
		return nil, fmt.Errorf("rewrite: unknown reply_to %q", r.ReplyTo)
	}
	return out, nil
}

func compilePattern(s string) (pattern, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "*@") {
		d := strings.ToLower(s[2:])
		if !config.ValidDomain(d) {
			return pattern{}, fmt.Errorf("rewrite: allowed_senders %q: invalid domain", s)
		}
		return pattern{domain: d}, nil
	}
	if !config.ValidAddress(s) {
		return pattern{}, fmt.Errorf("rewrite: allowed_senders %q must be an address or *@domain", s)
	}
	at := strings.LastIndex(s, "@")
	return pattern{local: s[:at], domain: strings.ToLower(s[at+1:])}, nil
}

// Mode reports the compiled mode, for logging and the configuration view.
func (r *Rules) Mode() string {
	if r == nil {
		return ModeOff
	}
	return r.mode
}

// Authorized reports whether sender matches allowed_senders.
func (r *Rules) Authorized(sender string) bool {
	if r == nil {
		return true
	}
	local, domain := splitAddress(sender)
	if domain == "" {
		return false
	}
	for _, p := range r.allowed {
		if p.domain != domain {
			continue
		}
		if p.local == "" || strings.EqualFold(p.local, local) {
			return true
		}
	}
	return false
}

// Input is one message as it stands after the listener has read it.
type Input struct {
	EnvelopeFrom string // validated MAIL FROM, empty for the null reverse path
	Headers      string // raw header block, CRLF line endings
}

// Result is the message after the policy has been applied. Headers is the
// block to spool; it equals Input.Headers when nothing was rewritten.
type Result struct {
	EnvelopeFrom string
	Headers      string
	Rewritten    bool
	OriginalFrom string // envelope sender before rewriting, for the queue record
}

// Apply enforces the client's policy. It returns an error only when the
// message cannot be rewritten safely, which the caller must turn into a
// permanent rejection rather than a queued message.
func (r *Rules) Apply(in Input) (Result, error) {
	res := Result{EnvelopeFrom: in.EnvelopeFrom, Headers: in.Headers}

	// The null reverse path belongs to a bounce and is never rewritten:
	// giving it a sender is how a notification loop starts.
	if r == nil || r.mode == ModeOff || in.EnvelopeFrom == "" {
		return res, nil
	}
	if r.mode == ModeIfUnauthorized && r.Authorized(in.EnvelopeFrom) {
		return res, nil
	}

	blk, err := parseBlock(in.Headers)
	if err != nil {
		return res, err
	}
	if blk.count("from") > 1 {
		return res, ErrAmbiguousFrom
	}

	orig := strings.TrimSpace(blk.value("from"))
	if orig != "" {
		if len(orig) > maxPreservedFrom {
			return res, ErrHeaderTooLong
		}
		if err := checkHeaderValue(orig); err != nil {
			return res, err
		}
	}

	if r.keepsFrom(orig) {
		// The From is already aligned with the new envelope sender, so only
		// the envelope changes and nothing is lost that needs preserving.
		res.EnvelopeFrom = r.envFrom
		res.Headers = blk.String()
		res.Rewritten = true
		res.OriginalFrom = in.EnvelopeFrom
		return res, nil
	}

	blk.set("From", r.fromValue())
	if orig != "" {
		blk.set("X-Original-From", orig)
	}

	switch r.replyTo {
	case replyDrop:
		blk.remove("reply-to")
	case replyFixed:
		blk.set("Reply-To", "<"+r.replyFixed+">")
	default:
		// A Reply-To the client set itself is left alone: it is a deliberate
		// statement about where answers go and rewriting did not invalidate
		// it.
		if !blk.has("reply-to") {
			if a := r.replyAddress(orig, in.EnvelopeFrom); a != "" {
				blk.set("Reply-To", "<"+a+">")
			}
		}
	}

	res.EnvelopeFrom = r.envFrom
	res.Headers = blk.String()
	res.Rewritten = true
	res.OriginalFrom = in.EnvelopeFrom
	return res, nil
}

// keepsFrom reports whether the original From survives, which it does only
// under header_from = "keep" and only while it stays aligned with the new
// envelope sender.
func (r *Rules) keepsFrom(orig string) bool {
	if r.headerFrom != HeaderFromKeep || orig == "" {
		return false
	}
	a := addrOfMailbox(orig)
	if !config.ValidAddress(a) {
		return false
	}
	return config.DomainOf(a) == config.DomainOf(r.envFrom)
}

func (r *Rules) fromValue() string {
	if r.headerFrom != "" && r.headerFrom != HeaderFromKeep {
		return r.headerFrom
	}
	return "<" + r.envFrom + ">"
}

// replyAddress picks where answers should go: the address the client put in
// its From header when that is usable, otherwise the envelope sender it
// declared. Both have been validated before they get here.
func (r *Rules) replyAddress(orig, envelope string) string {
	if a := addrOfMailbox(orig); config.ValidAddress(a) {
		if !strings.EqualFold(a, r.envFrom) {
			return a
		}
		return ""
	}
	if config.ValidAddress(envelope) && !strings.EqualFold(envelope, r.envFrom) {
		return envelope
	}
	return ""
}

// checkHeaderValue rejects control characters. Eight-bit octets are allowed
// through unchanged: legacy devices emit unencoded UTF-8 display names, and
// those cannot terminate a header line, which is the property that matters.
func checkHeaderValue(s string) error {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return ErrUnsafeHeader
		}
	}
	return nil
}

// addrOfMailbox extracts the addr-spec from a From value. A group list or a
// comment is not something to guess at, so it yields nothing.
func addrOfMailbox(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.LastIndex(s, "<"); i >= 0 {
		j := strings.Index(s[i:], ">")
		if j < 0 {
			return ""
		}
		return strings.TrimSpace(s[i+1 : i+j])
	}
	if strings.ContainsAny(s, "(),;:") {
		return ""
	}
	return s
}

func splitAddress(addr string) (local, domain string) {
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at == len(addr)-1 {
		return "", ""
	}
	return addr[:at], strings.ToLower(addr[at+1:])
}

// formatMailbox renders a display name and address. The display name has
// already been restricted to printable ASCII without quotes, backslashes or
// angle brackets, so quoting it can never escape the quoted string.
func formatMailbox(display, addr string) string {
	if display == "" {
		return "<" + addr + ">"
	}
	if needsQuoting(display) {
		return `"` + display + `" <` + addr + ">"
	}
	return display + " <" + addr + ">"
}

// needsQuoting reports whether display contains anything outside atext and
// spaces, in which case it must be a quoted-string to stay a valid phrase.
func needsQuoting(display string) bool {
	const atext = "!#$%&'*+-/=?^_`{|}~"
	for i := 0; i < len(display); i++ {
		c := display[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == ' ':
		case strings.IndexByte(atext, c) >= 0:
		default:
			return true
		}
	}
	return false
}
