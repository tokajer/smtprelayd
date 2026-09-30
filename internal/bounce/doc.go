// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package bounce is the relay's one channel for telling an operator
// something.
//
// Notifier batches permanent delivery failures into periodic digest
// notification mail: RecordFail only ever adds a queue ID to an in-memory
// bucket, and the digest itself is composed and sent later, on Run's own
// schedule, from what the history store already recorded. It carries loop
// prevention (a notification's own failure is never recorded as another
// bounce to report) and a per-hour volume cap, so a delivery-failure storm
// cannot become a mail storm of its own.
//
// Notifier.Notify is also the general operator notification channel other
// sources use to reuse the same contact details and loop-prevention
// properties rather than growing a second notion of "who to mail": a canary's
// permanent failure reaches the digest through the same path a real client's
// does, and internal/expiry's Watcher calls Notify directly, through the
// Notifier interface it declares on its own consumer side, for its own mail
// about a certificate or a client secret about to expire.
//
// Both answer to the same [bounce] configuration section: its notify list
// (and a client's or canary's own override, where one applies) is who every
// mail this package sends goes to.
package bounce
