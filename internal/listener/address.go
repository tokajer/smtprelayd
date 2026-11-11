// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"strings"

	"github.com/tokajer/smtprelayd/internal/mailaddr"
)

// maxLineOctet is the RFC 5321 section 4.5.3.1.6 text line limit. A line
// that exceeds it is rejected rather than truncated.
const maxLineOctet = 1000 // including CRLF

// errBadAddress is mailaddr.ErrEnvelope rather than a sentinel of its own:
// the check moved there so the spool can apply it to what it reads back, and
// one value keeps both the reply text and errors.Is unchanged.
var errBadAddress = mailaddr.ErrEnvelope

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

// validateAddress checks structure and length; see mailaddr.CheckEnvelope
// for why that is looser than mailaddr.ValidAddress. allowEmpty covers the
// null reverse path used by bounces.
func validateAddress(addr string, allowEmpty bool) error {
	if addr == "" && allowEmpty {
		return nil
	}
	return mailaddr.CheckEnvelope(addr)
}
