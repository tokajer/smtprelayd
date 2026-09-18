// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package delivery

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// queueList spools one message addressed to several recipients on one route,
// which is what router.Split produces for a distribution list.
func queueList(t *testing.T, sp *spool.Spool, st *store.Store, to ...string) (spool.ID, *spool.Meta) {
	t.Helper()
	now := time.Now().UTC()
	env := spool.Envelope{
		From: "device@example.at", To: to,
		Client: "printers", Route: "smarthost", Received: now,
	}
	id, err := sp.Enqueue(env, strings.NewReader("Subject: invoice\r\n\r\nbody\r\n"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := json.Marshal(to)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordMessage(store.MessageRecord{
		QueueID: id.String(), Client: "printers", Route: "smarthost",
		EnvelopeFrom: "device@example.at", Recipients: string(recipients),
		Listener: "l", RemoteAddr: "127.0.0.1", ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	meta, ok := sp.Claim(time.Now())
	if !ok {
		t.Fatal("nothing to claim")
	}
	return id, meta
}

// The regression this exists for. A mailbox that no longer exists is refused
// with a 550 at its own RCPT, and the message used to be bounced for
// everybody -- including the recipients the smarthost had already accepted
// with 250 in that same session. A printer mailing a three-person
// distribution list lost the mail for all three because one person had left.
func TestOneDeadRecipientDoesNotStopTheOthers(t *testing.T) {
	f := startSelectiveSmarthost(t,
		"250 2.1.5 recipient ok",
		"550 5.1.1 <gone@example.net>: recipient does not exist",
		"250 2.1.5 recipient ok",
	)
	m, sp, st := managerAgainst(t, f)
	id, meta := queueList(t, sp, st,
		"alice@example.net", "gone@example.net", "bob@example.net")

	m.attempt(context.Background(), meta)

	if sp.Has(id) {
		t.Error("the message is still queued although the smarthost accepted it for two of three recipients")
	}
	if got := statusOf(t, st, id); got != "delivered" {
		t.Fatalf("journal status %q, want delivered: alice and bob received it", got)
	}

	// The refusal has to survive somewhere an operator looks, or a mail that
	// did not arrive has no trace at all.
	msg, err := st.FindMessageByID(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Attempts) != 1 {
		t.Fatalf("want one recorded attempt, got %d", len(msg.Attempts))
	}
	if msg.Attempts[0].SMTPCode != 550 {
		t.Errorf("recorded code %d, want the 550 the refused recipient drew", msg.Attempts[0].SMTPCode)
	}
	if !strings.Contains(msg.Attempts[0].SMTPResp, "gone@example.net") {
		t.Errorf("recorded response %q does not name the refused address", msg.Attempts[0].SMTPResp)
	}
}

// Every recipient refused is still a permanent failure: there is nobody left
// to deliver to, and no retry changes that.
func TestEveryRecipientRefusedIsStillAPermanentFailure(t *testing.T) {
	f := startSelectiveSmarthost(t,
		"550 5.1.1 no such user",
		"550 5.1.1 no such user",
	)
	m, sp, st := managerAgainst(t, f)
	id, meta := queueList(t, sp, st, "gone@example.net", "also-gone@example.net")

	m.attempt(context.Background(), meta)

	if got := statusOf(t, st, id); got != "bounced" {
		t.Errorf("journal status %q, want bounced", got)
	}
	if sp.Len() != 0 {
		t.Error("a permanently failed message must leave the live queue")
	}
}

// A *temporarily* refused recipient must still defer the whole message,
// before anything is sent. The message has to be retried for that recipient,
// and it cannot be retried for one recipient without being delivered a second
// time to the others: a queued message is one envelope, not one per address.
func TestATemporarilyRefusedRecipientDefersTheWholeMessage(t *testing.T) {
	f := startSelectiveSmarthost(t,
		"250 2.1.5 recipient ok",
		"451 4.3.0 mailbox temporarily unavailable",
	)
	m, sp, st := managerAgainst(t, f)
	id, meta := queueList(t, sp, st, "alice@example.net", "busy@example.net")

	m.attempt(context.Background(), meta)

	if !sp.Has(id) {
		t.Fatal("a temporarily refused recipient must leave the message queued for a retry")
	}
	if got := statusOf(t, st, id); got != "deferred" {
		t.Errorf("journal status %q, want deferred", got)
	}
}

// An ordinary full delivery records no SMTP response, so the partial case
// above is distinguishable from it rather than being noise on every row.
func TestAFullDeliveryRecordsNoRefusal(t *testing.T) {
	f := startFakeSmarthost(t, "250 2.0.0 accepted")
	m, sp, st := managerAgainst(t, f)
	id, meta := queueList(t, sp, st, "alice@example.net", "bob@example.net")

	m.attempt(context.Background(), meta)

	msg, err := st.FindMessageByID(id.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Attempts) != 1 {
		t.Fatalf("want one recorded attempt, got %d", len(msg.Attempts))
	}
	if msg.Attempts[0].SMTPCode != 0 || msg.Attempts[0].SMTPResp != "" {
		t.Errorf("a clean delivery recorded %d %q, want neither",
			msg.Attempts[0].SMTPCode, msg.Attempts[0].SMTPResp)
	}
}
