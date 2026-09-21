// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"context"
	"os"
	"time"

	kservice "github.com/kardianos/service"
)

// windowsServiceConfig is shared by install, uninstall, start, stop and the
// SCM-invoked run path, so the registered service always matches what "run"
// would start under the SCM.
func windowsServiceConfig() *kservice.Config {
	return &kservice.Config{
		Name:        "smtprelayd",
		DisplayName: "SMTP Relay Service",
		Description: "Accepts SMTP submissions from trusted internal devices and forwards them to a smarthost.",
		Arguments:   []string{"run"},
		// A virtual service account needs no password and no manual account
		// creation, and is never LocalSystem. See docs/dev/EXPLOIT-SURFACE.md.
		UserName: `NT SERVICE\smtprelayd`,
		Option: kservice.KeyValue{
			"StartType": kservice.ServiceStartAutomatic,
			"OnFailure": kservice.OnFailureRestart,
		},
	}
}

func isWindowsService() bool {
	return !kservice.Interactive()
}

func controlService(action, configPath string) error {
	s, err := kservice.New(&winProgram{configPath: configPath}, windowsServiceConfig())
	if err != nil {
		return err
	}
	return kservice.Control(s, action)
}

// winProgram adapts serve() to the kardianos/service Start/Stop lifecycle.
// Start must return quickly, so the relay runs in a goroutine — but it
// blocks that quick return on serve's ready signal, so a startup failure
// (bad configuration, a spool/store that would not open, a port already
// bound, a rejected OAuth2 credential) is reported to the SCM as a failed
// start instead of silently leaving a dead process reported as running. Stop
// cancels the context serve() was given and waits for it to unwind.
type winProgram struct {
	configPath string
	console    bool
	cancel     context.CancelFunc
	done       chan error
}

// readyWait bounds how long Start blocks on the ready signal.
//
// The SCM gives a service 30 seconds to report SERVICE_RUNNING
// (ServicesPipeTimeout) and kardianos/service offers no way to send
// SERVICE_START_PENDING in the meantime, so a slow start is simply killed --
// and windowsServiceConfig sets OnFailureRestart, so it is killed and started
// again, forever. What makes a start slow is spool.Open rebuilding the index
// from the queue directory: measured at 8.7 seconds for 100 000 queued
// messages on a Windows VM and rising faster than linearly, so a backlog of a
// few hundred thousand crosses the limit. That backlog is exactly what a
// smarthost outage leaves behind, which made the restart loop a consequence
// of the outage rather than of anything wrong with the service.
//
// Twenty seconds keeps the useful half of blocking -- a configuration error,
// a port already bound, a rejected credential all surface in well under a
// second and are still reported as a failed start -- and gives up the part
// that was doing harm.
const readyWait = 20 * time.Second

func (p *winProgram) Start(s kservice.Service) error {
	var ctx context.Context
	ctx, p.cancel = context.WithCancel(context.Background())
	p.done = make(chan error, 1)
	ready := make(chan error, 1)
	go func() { p.done <- serve(ctx, p.configPath, p.console, ready) }()

	err, settled := awaitReady(ready, readyWait)
	if settled {
		return err
	}
	// Report running and keep going. The startup is still in flight; if it
	// fails after this point the watchdog below ends the process, and the
	// SCM's restart policy applies to it the way it would to any later crash.
	if logger, lerr := s.Logger(nil); lerr == nil {
		_ = logger.Warning("smtprelayd: startup is taking longer than " +
			readyWait.String() + ", reporting running so the service is not killed; " +
			"a large spool backlog is the usual cause")
	}
	go p.watchStartup(s, ready)
	return nil
}

// awaitReady waits for the startup verdict, giving up after limit. settled
// says whether the verdict arrived: a false settled means startup is still
// running and its outcome is not known yet, which is not the same as success
// and must not be returned as one.
func awaitReady(ready <-chan error, limit time.Duration) (err error, settled bool) {
	select {
	case err := <-ready:
		return err, true
	case <-time.After(limit):
		return nil, false
	}
}

// watchStartup ends the process if a startup that was reported as running
// turns out to have failed. ready carries exactly one value, whenever serve
// reaches its verdict.
func (p *winProgram) watchStartup(s kservice.Service, ready <-chan error) {
	err := <-ready
	if err == nil {
		return
	}
	if logger, lerr := s.Logger(nil); lerr == nil {
		_ = logger.Error("smtprelayd: startup failed after the service was reported running: " + err.Error())
	}
	os.Exit(1)
}

func (p *winProgram) Stop(s kservice.Service) error {
	p.cancel()
	<-p.done
	return nil
}

func runWindowsService(configPath string, console bool) error {
	prg := &winProgram{configPath: configPath, console: console}
	s, err := kservice.New(prg, windowsServiceConfig())
	if err != nil {
		return err
	}
	logger, logErr := s.Logger(nil)
	if err := s.Run(); err != nil {
		if logErr == nil {
			logger.Error(err)
		}
		return err
	}
	return nil
}
