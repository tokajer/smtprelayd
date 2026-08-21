// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// csrfSigner issues and verifies short-lived, per-action tokens for the
// dashboard's requeue and delete forms. The dashboard has no login and no
// session of its own — loopback binding is its trust boundary, per the
// phase 4c decision to skip web authentication entirely — so there is no
// session identifier to bind a token to; the per-process random key plays
// that role instead. This still defeats the threat CSRF protection exists
// for here: a page that merely has network access to the dashboard cannot
// forge a token it never saw, because it cannot reproduce this process's key.
type csrfSigner struct {
	key [32]byte
}

func newCSRFSigner() (*csrfSigner, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	return &csrfSigner{key: key}, nil
}

// csrfTokenTTL matches the one hour docs/dev/PHASE4-PLAN.md specifies.
const csrfTokenTTL = time.Hour

func (s *csrfSigner) token(action, queueID string, now time.Time) string {
	exp := now.Add(csrfTokenTTL).Unix()
	return fmt.Sprintf("%d.%s", exp, hex.EncodeToString(s.mac(action, queueID, exp)))
}

func (s *csrfSigner) mac(action, queueID string, exp int64) []byte {
	h := hmac.New(sha256.New, s.key[:])
	fmt.Fprintf(h, "%s|%s|%d", action, queueID, exp)
	return h.Sum(nil)
}

// verify checks a token against the action and queue ID it was issued for.
// A token issued for one action or one message never validates for another,
// so a form for message A cannot be replayed against message B.
func (s *csrfSigner) verify(token, action, queueID string, now time.Time) bool {
	dot := strings.IndexByte(token, '.')
	if dot < 0 {
		return false
	}
	exp, err := strconv.ParseInt(token[:dot], 10, 64)
	if err != nil || now.Unix() > exp {
		return false
	}
	given, err := hex.DecodeString(token[dot+1:])
	if err != nil {
		return false
	}
	return hmac.Equal(given, s.mac(action, queueID, exp))
}
