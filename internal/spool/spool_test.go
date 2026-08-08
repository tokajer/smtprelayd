// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package spool

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnqueueClaimRemove(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{From: "a@example.at", To: []string{"b@example.net"}, Client: "c", Route: "r",
		Received: time.Now().UTC()}
	id, err := s.Enqueue(env, strings.NewReader("Subject: x\r\n\r\nbody\r\n"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := s.Claim(time.Now())
	if !ok || m.ID != id {
		t.Fatalf("Claim returned %v %v", m, ok)
	}
	if _, ok := s.Claim(time.Now()); ok {
		t.Fatal("a leased message was handed out twice")
	}
	f, err := s.Open(id)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if !strings.Contains(string(b), "body") {
		t.Fatalf("body not stored: %q", b)
	}
	if err := s.Remove(id); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 0 {
		t.Fatalf("queue length %d after removal", s.Len())
	}
}

func TestEnqueueEnforcesSizeLimit(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Enqueue(Envelope{}, strings.NewReader(strings.Repeat("x", 2048)), 1024, time.Hour)
	if err != ErrTooLarge {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	// An aborted enqueue must not leave anything behind.
	entries, _ := os.ReadDir(filepath.Join(dir, "spool", "tmp"))
	if len(entries) != 0 {
		t.Fatalf("tmp directory not cleaned: %v", entries)
	}
	if s.Len() != 0 {
		t.Fatalf("queue length %d after a rejected enqueue", s.Len())
	}
}

func TestRecoveryDropsOrphanedBody(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Enqueue(Envelope{From: "a@example.at"}, strings.NewReader("x"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash between the body and the metadata rename.
	if err := os.Remove(filepath.Join(dir, "spool", "queue", id.String()+".json")); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 0 {
		t.Fatalf("orphaned body was recovered as a message")
	}
	if _, err := os.Stat(filepath.Join(dir, "spool", "queue", id.String()+".eml")); !os.IsNotExist(err) {
		t.Fatal("orphaned body was not removed")
	}
}

func TestFailMovesAside(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	id, err := s.Enqueue(Envelope{From: "a@example.at"}, strings.NewReader("x"), 0, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := s.Claim(time.Now())
	if err := s.Fail(m, "550 rejected"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "spool", "failed", id.String()+".eml")); err != nil {
		t.Fatalf("failed message was not preserved: %v", err)
	}
}
