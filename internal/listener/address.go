// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"errors"
	"fmt"
	"strings"
)

// RFC 5321 section 4.5.3.1 size limits. Exceeding them is rejected rather
// than truncated, because a truncated address is a misdelivered message.
const (
	maxLocalPart = 64
	maxDomain    = 255
	maxPath      = 254
	maxLineOctet = 1000 // including CRLF
)

var errBadAddress = errors.New("malformed address")

// parsePath extracts the address from a MAIL FROM or RCPT TO argument of the
// form "<addr>" optionally followed by ESMTP parameters. Anything containing
// a control character is rejected outright and never sanitised: sanitising is
// how a CRLF ends up injected into a header two layers further down.
func parsePath(arg string) (addr string, params []string, err error) {
	arg = strings.TrimLeft(arg, " \t")
	if !strings.HasPrefix(arg, "<") {
		return "", nil, errBadAddress
	}
	end := strings.Index(arg, ">")
	if end < 0 {
		return "", nil, errBadAddress
	}
	addr = arg[1:end]
	rest := strings.TrimSpace(arg[end+1:])
	if rest != "" {
		params = strings.Fields(rest)
	}
	if err := validateAddress(addr, true); err != nil {
		return "", nil, err
	}
	return addr, params, nil
}

// validateAddress checks structure and length. allowEmpty covers the null
// reverse path used by bounces.
func validateAddress(addr string, allowEmpty bool) error {
	if addr == "" {
		if allowEmpty {
			return nil
		}
		return errBadAddress
	}
	if len(addr) > maxPath {
		return fmt.Errorf("%w: longer than %d octets", errBadAddress, maxPath)
	}
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("%w: control character", errBadAddress)
		}
	}
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at == len(addr)-1 {
		return fmt.Errorf("%w: expected local@domain", errBadAddress)
	}
	local, domain := addr[:at], addr[at+1:]
	if len(local) > maxLocalPart {
		return fmt.Errorf("%w: local part longer than %d octets", errBadAddress, maxLocalPart)
	}
	if len(domain) > maxDomain {
		return fmt.Errorf("%w: domain longer than %d octets", errBadAddress, maxDomain)
	}
	if strings.ContainsAny(domain, " \t<>,;\"\\") || strings.Contains(domain, "..") ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("%w: malformed domain", errBadAddress)
	}
	return nil
}

// domainOf returns the recipient domain in lower case, for route selection.
func domainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}
