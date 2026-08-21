// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"context"

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

func (p *winProgram) Start(s kservice.Service) error {
	var ctx context.Context
	ctx, p.cancel = context.WithCancel(context.Background())
	p.done = make(chan error, 1)
	ready := make(chan error, 1)
	go func() { p.done <- serve(ctx, p.configPath, p.console, ready) }()
	return <-ready
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
