// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

import "strings"

// RFC 5321 section 4.5.3.1 length limits, repeated here because the rewriter
// validates configured addresses before they reach a header and must not
// depend on the listener package.
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
