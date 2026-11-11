// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/tokajer/smtprelayd/internal/ostrust"
)

// The SCM gives a service 30 seconds to report SERVICE_RUNNING and kills it
// otherwise -- and windowsServiceConfig asks for a restart on failure, so a
// start that is merely slow becomes an endless restart loop. Start used to
// block on the ready signal without a bound, and what makes it slow is
// spool.Open: 8.7 seconds for 100 000 queued messages on a Windows VM, rising
// faster than linearly. A backlog left by a smarthost outage was therefore
// enough to stop the service from ever starting again.
func TestAwaitReadyGivesUpBeforeTheSCMDoes(t *testing.T) {
	if readyWait >= 30*time.Second {
		t.Fatalf("readyWait is %v; the SCM's own limit is 30s, so this never fires", readyWait)
	}

	never := make(chan error) // a startup still in flight
	start := time.Now()
	err, settled := awaitReady(never, 50*time.Millisecond)
	elapsed := time.Since(start)

	if settled {
		t.Error("a startup that has not finished was reported as settled")
	}
	if err != nil {
		t.Errorf("an unfinished startup reported error %v; it has no verdict yet", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("awaitReady waited %v past its limit", elapsed)
	}
}

// The half of blocking that was worth keeping: a startup that fails fast --
// a bad configuration, a bound port, a rejected credential -- is still
// reported to the SCM as a failed start rather than as a running service.
func TestAwaitReadyReturnsAFastFailure(t *testing.T) {
	want := errors.New("configuration is not valid")
	ready := make(chan error, 1)
	ready <- want

	err, settled := awaitReady(ready, 5*time.Second)
	if !settled {
		t.Fatal("a verdict that was already available was not picked up")
	}
	if !errors.Is(err, want) {
		t.Errorf("got %v, want the startup error %v", err, want)
	}
}

// And a successful start still reports success.
func TestAwaitReadyReturnsSuccess(t *testing.T) {
	ready := make(chan error, 1)
	ready <- nil
	if err, settled := awaitReady(ready, 5*time.Second); !settled || err != nil {
		t.Errorf("a successful start reported (%v, settled=%v)", err, settled)
	}
}

// The DACL every install writes has to pass the check that reads it back, or
// every install fails; this runs without elevation, unlike the test below.
func TestServiceSDDLPassesItsOwnCheck(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(serviceSDDL)
	if err != nil {
		t.Fatal(err)
	}
	if err := ostrust.CheckServiceDACL(sd); err != nil {
		t.Fatalf("serviceSDDL is refused by CheckServiceDACL: %v", err)
	}
}

// And the check is not vacuous: full control for Authenticated Users, the
// shape a weak service ACL takes in the wild, is refused.
func TestCheckServiceDACLRefusesAWeakDACL(t *testing.T) {
	for _, weak := range []string{
		serviceSDDL + "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;AU)",
		serviceSDDL + "(A;;DC;;;IU)", // SERVICE_CHANGE_CONFIG alone is enough
		serviceSDDL + "(A;;GA;;;BU)",
		"D:NO_ACCESS_CONTROL",
	} {
		sd, err := windows.SecurityDescriptorFromString(weak)
		if err != nil {
			t.Fatal(err)
		}
		if err := ostrust.CheckServiceDACL(sd); err == nil {
			t.Errorf("%s was accepted", weak)
		}
	}
}

// docs/dev/EXPLOIT-SURFACE.md section 2 asks for two things a test must
// assert: that the registered command line quotes an executable path with a
// space in it, and that the service carries an explicit restrictive DACL.
// This runs the install path the MSI runs, under a throwaway name and from a
// path with a space, and reads both back. The executable does not have to
// exist: neither CreateService nor kardianos checks, and the service is
// never started.
//
// It needs an elevated token to talk to the SCM with create rights, which
// GitHub's windows-latest runner has, so CI runs it; a developer prompt
// without elevation skips it.
func TestInstallServiceQuotesThePathAndRestrictsTheDACL(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("installing a service needs an elevated prompt; run the tests as administrator to cover this")
	}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	cfg := windowsServiceConfig()
	cfg.Name = "smtprelayd-test-" + hex.EncodeToString(suffix[:])
	cfg.DisplayName = cfg.Name
	// The virtual account has to name the service it belongs to; this keeps
	// the real configuration's shape for the throwaway name.
	cfg.UserName = `NT SERVICE\` + cfg.Name
	cfg.Executable = filepath.Join(t.TempDir(), "with space", "smtprelayd.exe")

	// Registered before the install, so a failure halfway through still
	// removes whatever exists by then.
	t.Cleanup(func() {
		m, err := mgr.Connect()
		if err != nil {
			t.Errorf("cleanup: %v", err)
			return
		}
		defer m.Disconnect()
		if s, err := m.OpenService(cfg.Name); err == nil {
			// installService deletes the service itself when it fails
			// after creating it; the name stays openable until the last
			// handle closes, and deleting it again reports that.
			if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
				t.Errorf("cleanup: deleting service %s: %v", cfg.Name, err)
			}
			_ = s.Close()
		}
		_ = eventlog.Remove(cfg.Name)
	})

	if err := installService(cfg); err != nil {
		t.Fatalf("installService: %v", err)
	}
	if err := checkServiceSecurity(cfg.Name, cfg.Executable); err != nil {
		t.Fatal(err)
	}

	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(cfg.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		t.Fatal(err)
	}
	// Stated here as well as in checkServiceSecurity, so that loosening that
	// check cannot also silently loosen this test.
	if want := `"` + cfg.Executable + `" run`; c.BinaryPathName != want {
		t.Errorf("registered command line is %q, want %q", c.BinaryPathName, want)
	}
	if !strings.EqualFold(c.ServiceStartName, cfg.UserName) {
		t.Errorf("service runs as %q, want %q", c.ServiceStartName, cfg.UserName)
	}
}

// An unquoted path with a space is the hijack: the SCM tries each prefix
// that ends at a space, so C:\Program.exe runs before the real binary.
// harden-service judges an existing registration by its command line alone,
// so the rule has to hold without knowing which path was meant.
func TestUnquotedWithSpace(t *testing.T) {
	for _, tc := range []struct {
		cmdline string
		bad     bool
	}{
		{`"C:\Program Files\SMTPRelayd\smtprelayd.exe" run`, false},
		{`C:\SMTPRelayd\smtprelayd.exe run`, false},
		{`C:\SMTPRelayd\smtprelayd.exe`, false},
		{`C:\Program Files\SMTPRelayd\smtprelayd.exe run`, true},
		{`C:\Program Files\SMTPRelayd\smtprelayd.EXE run`, true},
		// A directory whose name ends in .exe must not end the path early.
		{`C:\my.exe dir\smtprelayd.exe run`, true},
	} {
		if got := unquotedWithSpace(tc.cmdline); got != tc.bad {
			t.Errorf("unquotedWithSpace(%q) = %v, want %v", tc.cmdline, got, tc.bad)
		}
	}
}
