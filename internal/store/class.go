// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package store

// Class is the outcome of one delivery attempt as the journal records it.
type Class string

const (
	ClassDelivered Class = "delivered"
	ClassTemporary Class = "temporary"
	ClassPermanent Class = "permanent"
	ClassExpired   Class = "expired"
	ClassRemoved   Class = "removed"
)

// Message statuses, derived from the latest attempt's class.
const (
	StatusQueued    = "queued"
	StatusDeferred  = "deferred"
	StatusDelivered = "delivered"
	StatusBounced   = "bounced"
	StatusRemoved   = "removed"
	// StatusActive is a filter only: queued or deferred, i.e. still in the spool.
	StatusActive = "active"
)

// classStatus is the single class->status mapping. Every other table in this
// package that relates a class to a status is derived from it, so the two
// cannot silently drift apart the way two hand-written switches could.
var classStatus = map[Class]string{
	ClassDelivered: StatusDelivered,
	ClassTemporary: StatusDeferred,
	ClassPermanent: StatusBounced,
	ClassExpired:   StatusBounced,
	ClassRemoved:   StatusRemoved,
}

// statusClasses is classStatus inverted: which classes produce a given
// status. Derived rather than written out by hand, so the two tables cannot
// disagree; the query that consumes it (FindMessages) only tests class
// membership, so the order within each slice does not matter.
var statusClasses = func() map[string][]Class {
	out := map[string][]Class{}
	for c, s := range classStatus {
		out[s] = append(out[s], c)
	}
	return out
}()

// classToStatus derives a message's display status from its latest attempt.
// hasAttempt is false for a message with no attempts at all, which is
// "queued" regardless of class. An unknown class -- reachable only from a
// hand-edited database -- reads as "deferred", the same answer a class with
// no attempt-visible failure gets: not delivered, not removed, still worth
// showing as in progress rather than as an error.
func classToStatus(class Class, hasAttempt bool) string {
	if !hasAttempt {
		return StatusQueued
	}
	if s, ok := classStatus[class]; ok {
		return s
	}
	return StatusDeferred
}

// ValidBounceClass reports whether s is an acceptable value for a bounce
// filter's class parameter: no filter, or one of the classes that actually
// produce the "bounced" status.
func ValidBounceClass(s string) bool {
	return s == "" || classStatus[Class(s)] == StatusBounced
}
