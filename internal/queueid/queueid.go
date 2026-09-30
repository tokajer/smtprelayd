// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package queueid defines the validated queue identifier type shared by the
// spool, the store, and everything that references a message by ID.
package queueid

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"regexp"
)

// ID identifies a queued message. It is a named type with a private
// construction path so that a caller cannot pass an arbitrary string where a
// queue ID is expected; every file name in the spool is derived from a value
// that went through New or Parse.
type ID string

var idPattern = regexp.MustCompile(`^[A-Z2-7]{16}$`)

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrInvalid is returned for any value that is not a well-formed queue ID.
var ErrInvalid = errors.New("queueid: invalid queue id")

// New returns a fresh random queue ID. 80 bits of entropy is far more than
// collision resistance needs and keeps the identifier short enough to appear
// in a Received header.
func New() (ID, error) {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return ID(encoding.EncodeToString(b[:])), nil
}

// Parse validates an externally supplied identifier.
func Parse(s string) (ID, error) {
	if !idPattern.MatchString(s) {
		return "", ErrInvalid
	}
	return ID(s), nil
}

func (id ID) String() string { return string(id) }

// Valid guards every internal path construction.
func (id ID) Valid() bool { return idPattern.MatchString(string(id)) }
