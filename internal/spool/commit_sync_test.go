// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package spool

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A commit whose directory sync fails must leave nothing behind.
//
// Both files are renamed into the queue directory before the sync, so until
// 2026-09-21 a failing sync returned an error with the pair still on disk and
// nothing in the index: invisible to ClaimBatch, to QueueDepth and to the
// quota for the life of the process, then re-indexed by recover() at the next
// start and delivered -- while the listener, told the commit failed, had
// already withdrawn the sibling copies and answered 4xx, so the client had
// retried. One failed fsync, one message delivered twice.
func TestCommitLeavesNothingBehindWhenTheDirectorySyncFails(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("sync failed")
	original := syncDirFn
	syncDirFn = func(string) error { return wantErr }
	t.Cleanup(func() { syncDirFn = original })

	st, err := s.Stage(strings.NewReader("body"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Discard()

	env := Envelope{From: "device@example.at", To: []string{"ops@example.at"}, Route: "m365"}
	if _, err := s.Commit(st, env, time.Hour, nil); !errors.Is(err, wantErr) {
		t.Fatalf("commit error = %v, want %v", err, wantErr)
	}

	if n := s.Len(); n != 0 {
		t.Errorf("index holds %d messages after a failed commit, want 0", n)
	}
	entries, err := os.ReadDir(s.queue)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("queue directory still holds %s: recover() would re-index it "+
			"and deliver a message the caller was told was not accepted", e.Name())
	}

	// And the proof of that last claim: a restart finds an empty queue.
	syncDirFn = original
	reopened, err := Open(filepath.Dir(filepath.Dir(s.queue)))
	if err != nil {
		t.Fatal(err)
	}
	if n := reopened.Len(); n != 0 {
		t.Errorf("a restart re-indexed %d message(s) from a commit that failed", n)
	}
}
