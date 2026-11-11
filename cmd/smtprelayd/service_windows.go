// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	kservice "github.com/kardianos/service"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/tokajer/smtprelayd/internal/ostrust"
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
	if action == "install" {
		return installService(windowsServiceConfig())
	}
	s, err := kservice.New(&winProgram{configPath: configPath}, windowsServiceConfig())
	if err != nil {
		return err
	}
	return kservice.Control(s, action)
}

// serviceSDDL is the DACL install and harden-service write onto the service:
// SYSTEM may query, start and stop it, Administrators have full control,
// interactive and service logons may only query it, and nobody else may do
// anything.
//
// The default the SCM applies is close to this, but a default is whatever the
// Windows build, a GPO or a hardening baseline left it as, and
// docs/dev/EXPLOIT-SURFACE.md section 2 asks for an explicit one: an account
// holding SERVICE_CHANGE_CONFIG can point the binary path anywhere and run
// it as the service account -- or as LocalSystem, by changing that too.
const serviceSDDL = "D:P" +
	"(A;;CCLCSWRPWPDTLOCRRC;;;SY)" +
	"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" +
	"(A;;CCLCSWLOCRRC;;;IU)" +
	"(A;;CCLCSWLOCRRC;;;SU)"

// installService registers cfg with the SCM, then hardens it the way
// harden-service does and reads the registered command line back against
// the executable just registered. cfg is a parameter, not
// windowsServiceConfig() itself, so the test can run this same path under a
// throwaway name.
//
// A failure after the service exists deletes it again before returning: the
// MSI runs this as a custom action and fails the installation on the error,
// and a service left registered with the default DACL would be exactly the
// weak service this exists to prevent, sitting there for the next attempt to
// find with "already exists". That includes a failure inside kardianos's own
// Install, which can fail after CreateService has succeeded -- setting the
// recovery actions, registering the event source -- and leave the service
// behind; it reports "already exists" only as formatted text, so whether the
// service existed is asked of the SCM before the call instead.
func installService(cfg *kservice.Config) error {
	s, err := kservice.New(&winProgram{}, cfg)
	if err != nil {
		return err
	}
	existed, err := serviceExists(cfg.Name)
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if err := kservice.Control(s, "install"); err != nil {
		if !existed {
			if now, _ := serviceExists(cfg.Name); now {
				return errors.Join(err, s.Uninstall())
			}
		}
		return err
	}
	// Resolved the way kardianos resolves it for CreateService, so the
	// read-back below compares against the path that was registered.
	exe, err := os.Executable()
	if cfg.Executable != "" {
		exe, err = filepath.Abs(cfg.Executable)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("install: %w", err), s.Uninstall())
	}
	if err := hardenService(cfg.Name); err != nil {
		return errors.Join(fmt.Errorf("install: %w", err), s.Uninstall())
	}
	if err := checkServiceSecurity(cfg.Name, exe); err != nil {
		return errors.Join(fmt.Errorf("install: %w", err), s.Uninstall())
	}
	return nil
}

// serviceExists asks the SCM whether a service of that name is registered.
func serviceExists(name string) (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()
	svc, err := m.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_ = svc.Close()
	return true, nil
}

// hardenInstalledService is the harden-service command: serviceSDDL onto the
// registered smtprelayd service, then the same read-back install runs.
//
// It exists because install is not the only way a service comes to be: the
// MSI registers it only on a first installation and an upgrade keeps the
// existing registration, so a service installed before install wrote a DACL
// would otherwise keep the SCM's default for good. The MSI runs this on every
// installation and upgrade; it is idempotent, and it fails rather than
// creating anything when the service does not exist.
func hardenInstalledService() error {
	name := windowsServiceConfig().Name
	if err := hardenService(name); err != nil {
		return err
	}
	if err := checkServiceSecurity(name, ""); err != nil {
		return err
	}
	fmt.Printf("smtprelayd: service DACL set on %s\n", name)
	return nil
}

// hardenService replaces the service's DACL with serviceSDDL.
func hardenService(name string) error {
	sd, err := windows.SecurityDescriptorFromString(serviceSDDL)
	if err != nil {
		return fmt.Errorf("service DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("service DACL: %w", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	svc, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("opening service %s: %w", name, err)
	}
	defer svc.Close()
	err = windows.SetSecurityInfo(svc.Handle, windows.SE_SERVICE,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("setting the DACL of service %s: %w", name, err)
	}
	return nil
}

// checkServiceSecurity reads back the two properties of a registered service
// that docs/dev/EXPLOIT-SURFACE.md section 2 asks to be asserted rather than
// assumed: that an executable path containing a space is quoted -- unquoted,
// the SCM tries C:\Program.exe first, and whoever can write C:\ chooses what
// runs -- and that the DACL lets nobody but SYSTEM and Administrators
// reconfigure the service. The quoting is x/sys's mgr.CreateService today;
// this is what notices if that, or the path kardianos hands it, changes.
//
// exe, when known, is the path just registered and must appear quoted
// exactly; harden-service passes "" because an existing registration may
// name a path other than the running binary's, and only the shape of the
// command line can be judged then.
func checkServiceSecurity(name, exe string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	svc, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("opening service %s: %w", name, err)
	}
	defer svc.Close()

	c, err := svc.Config()
	if err != nil {
		return fmt.Errorf("service %s: reading its configuration: %w", name, err)
	}
	if unquotedWithSpace(c.BinaryPathName) ||
		(strings.ContainsAny(exe, " \t") && !strings.HasPrefix(c.BinaryPathName, `"`+exe+`"`)) {
		return fmt.Errorf("service %s: the executable path contains a space and is registered unquoted as %q; "+
			"remove the service with \"smtprelayd uninstall\" and install it again", name, c.BinaryPathName)
	}

	sd, err := windows.GetSecurityInfo(svc.Handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("service %s: reading its DACL: %w", name, err)
	}
	if err := ostrust.CheckServiceDACL(sd); err != nil {
		return fmt.Errorf("service %s: %w; run \"smtprelayd harden-service\" from an elevated prompt", name, err)
	}
	return nil
}

// unquotedWithSpace reports whether a registered command line leaves an
// executable path with a space in it unquoted. Without quotes the path ends
// wherever the SCM finds an executable, so everything up to the last ".exe"
// is taken as the path: the arguments this relay registers never contain
// one, and a path such as C:\my.exe dir\smtprelayd.exe is refused rather
// than read as C:\my.exe with arguments.
func unquotedWithSpace(cmdline string) bool {
	if strings.HasPrefix(cmdline, `"`) {
		return false
	}
	end := strings.LastIndex(strings.ToLower(cmdline), ".exe")
	if end < 0 {
		end = len(cmdline)
	}
	return strings.ContainsAny(cmdline[:end], " \t")
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
