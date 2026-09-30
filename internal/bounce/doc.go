// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package bounce is the relay's one channel for telling an operator
// something, and does three jobs with it.
//
// Notifier batches permanent delivery failures into periodic digest
// notification mail: RecordFail only ever adds a queue ID to an in-memory
// bucket, and the digest itself is composed and sent later, on Run's own
// schedule, from what the history store already recorded. It carries loop
// prevention (a notification's own failure is never recorded as another
// bounce to report) and a per-hour volume cap, so a delivery-failure storm
// cannot become a mail storm of its own.
//
// Notifier.Notify is the general operator notification channel other
// sources use to reuse the same contact details and loop-prevention
// properties rather than growing a second notion of "who to mail": a canary's
// permanent failure reaches the digest through the same path a real client's
// does, and ExpiryWatcher, below, calls Notify directly for its own mail.
//
// ExpiryWatcher mails the operator before something the relay depends on
// stops working: its own TLS certificate, or a Microsoft 365 client secret.
// It answers "is this deadline worth a mail, and if so, send one", built on
// top of internal/expiry, which only ever answers "what expires and when".
//
// All three answer to the same [bounce] configuration section: its notify
// list (and a client's or canary's own override, where one applies) is who
// every mail this package sends goes to.
package bounce
