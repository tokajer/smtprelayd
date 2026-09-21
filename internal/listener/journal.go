// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package listener

import (
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tokajer/smtprelayd/internal/rewrite"
	"github.com/tokajer/smtprelayd/internal/router"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// The history journal's view of an accepted message. Kept apart from the
// SMTP dialogue in session.go: what is recorded about a message, and how a
// header value is made safe to store, is not protocol handling, and this is
// the half of the file a change to the journal schema touches.

// journalAccepted records one queued copy in the history store. The write is
// best-effort: the message is already queued for delivery, and a problem in
// the history store must not undo that or fail the session over it. It is
// not silent, though: a failure is logged and counted, because until
// 2026-09-18 the error was discarded and a database that had stopped
// accepting writes showed up only as a queue view that no longer listed new
// mail.
func (s *session) journalAccepted(id spool.ID, g router.Group, res rewrite.Result, received time.Time, size int64, lifetime time.Duration) string {
	// Subject is stored only if retain_subjects is enabled; store.RecordMessage
	// redacts it again regardless, this just avoids parsing the header block
	// for nothing.
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
	err := s.srv.store.RecordMessage(store.MessageRecord{
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
		SizeBytes:    size,
		HeaderCount:  rewrite.HeaderCount(res.Headers),
		Helo:         sanitizeHeaderMeta(s.helo, maxStoredHelo),
		ReceivedAt:   received,
		ExpiresAt:    received.Add(lifetime),
		TLSUsed:      s.isTLS,
	})
	if err != nil {
		s.log.Warn("history journal write failed", "queue_id", id.String(), "error", err)
		if s.srv.metrics != nil {
			s.srv.metrics.JournalWriteFailure()
		}
	}
	return messageID
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
