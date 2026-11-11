// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package mailaddr validates the address syntax the relay accepts.
//
// It is a stdlib-only leaf package: internal/config uses it to validate
// addresses written into the configuration file, and internal/rewrite uses
// it to validate and reconstruct addresses in the mail it rewrites. The
// syntax rules have one home here, independent of the configuration schema.
package mailaddr

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// RFC 5321 section 4.5.3.1 length limits.
const (
	maxLocalPart = 64
	maxDomainLen = 255
	maxPathLen   = 254
	maxDisplay   = 128
)

// ValidAddress reports whether s is an addr-spec that can be placed into an
// envelope or an angle-addr without further quoting. Anything outside
// printable ASCII is refused: an address that needs encoding is a
// configuration mistake, and guessing at one is how a header gets split.
func ValidAddress(s string) bool {
	if s == "" || len(s) > maxPathLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e {
			return false
		}
	}
	at := strings.LastIndex(s, "@")
	if at <= 0 || at == len(s)-1 {
		return false
	}
	local, domain := s[:at], s[at+1:]
	if len(local) > maxLocalPart || strings.ContainsAny(local, `<>,;:"\`) {
		return false
	}
	return ValidDomain(domain)
}

// ErrEnvelope is wrapped by every error CheckEnvelope returns. Its text is
// what the listener puts after the reply code, so it stays as it was when the
// check lived there.
var ErrEnvelope = errors.New("malformed address")

// CheckEnvelope checks the structure and length of an envelope address: a
// MAIL FROM or RCPT TO path as the listener accepts it, and the same address
// read back from the spool. The empty null reverse path is refused; whether
// it is acceptable is the caller's decision.
//
// This is deliberately looser than ValidAddress, which governs what an
// operator may write into a header: a device's envelope address may carry
// valid UTF-8 or a quoted local part and still be relayed as is, because it
// is only ever placed back into MAIL FROM and RCPT TO, never composed into a
// header line. What both refuse is the same -- control characters, an
// oversized part, a malformed domain, an angle bracket -- so an address that
// passes here cannot split a line downstream either.
//
// Eight-bit octets that are not valid UTF-8 are refused: the spool stores the
// envelope as JSON, and json.Marshal rewrites each invalid byte as U+FFFD, so
// the message read back after a restart would go to an address the client
// never named. An angle bracket is refused because it is the path delimiter:
// "MAIL FROM:<<a@b.example>" used to be accepted as "<a@b.example", which is
// a path no client meant and no smarthost parses the same way.
func CheckEnvelope(addr string) error {
	if addr == "" {
		return ErrEnvelope
	}
	if len(addr) > maxPathLen {
		return fmt.Errorf("%w: longer than %d octets", ErrEnvelope, maxPathLen)
	}
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("%w: control character", ErrEnvelope)
		}
	}
	if !utf8.ValidString(addr) {
		return fmt.Errorf("%w: not valid UTF-8", ErrEnvelope)
	}
	if strings.ContainsAny(addr, "<>") {
		return fmt.Errorf("%w: angle bracket", ErrEnvelope)
	}
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at == len(addr)-1 {
		return fmt.Errorf("%w: expected local@domain", ErrEnvelope)
	}
	local, domain := addr[:at], addr[at+1:]
	if len(local) > maxLocalPart {
		return fmt.Errorf("%w: local part longer than %d octets", ErrEnvelope, maxLocalPart)
	}
	if len(domain) > maxDomainLen {
		return fmt.Errorf("%w: domain longer than %d octets", ErrEnvelope, maxDomainLen)
	}
	if strings.ContainsAny(domain, " \t<>,;\"\\") || strings.Contains(domain, "..") ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("%w: malformed domain", ErrEnvelope)
	}
	return nil
}

// ValidDomain reports whether d is a plain LDH domain name. Address literals
// are deliberately not accepted: the relay never needs to send to one, and
// accepting them widens what may be interpolated into a header.
func ValidDomain(d string) bool {
	if d == "" || len(d) > maxDomainLen {
		return false
	}
	if strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || strings.Contains(d, "..") {
		return false
	}
	if !strings.Contains(d, ".") {
		return false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-':
		default:
			return false
		}
	}
	return true
}

// DomainOf returns the lower-cased domain of an address, or the empty string
// if there is none.
func DomainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

// SplitMailbox parses a configured header_from value, which is either a bare
// address or a display name followed by an angle-addr. The display name is
// restricted to printable ASCII without angle brackets, quotes or backslashes
// so that formatting it back into a header can never terminate the line or
// escape the quoted form.
func SplitMailbox(s string) (display, addr string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	if i := strings.LastIndex(s, "<"); i >= 0 {
		j := strings.LastIndex(s, ">")
		if j <= i {
			return "", "", false
		}
		display = strings.TrimSpace(s[:i])
		addr = strings.TrimSpace(s[i+1 : j])
	} else {
		addr = s
	}
	if !ValidAddress(addr) {
		return "", "", false
	}
	if len(display) > maxDisplay {
		return "", "", false
	}
	for i := 0; i < len(display); i++ {
		c := display[i]
		if c < 0x20 || c > 0x7e || c == '<' || c == '>' || c == '"' || c == '\\' {
			return "", "", false
		}
	}
	return display, addr, true
}

// ValidSenderPattern reports whether s is usable in rewrite.allowed_senders:
// either an exact address or *@domain. Broader wildcards are refused because
// an allowlist that is hard to read is one that is wrong.
func ValidSenderPattern(s string) bool {
	if strings.HasPrefix(s, "*@") {
		return ValidDomain(s[2:])
	}
	return ValidAddress(s)
}
