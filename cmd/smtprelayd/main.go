// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Command smtprelayd is an SMTP relay service for internal devices.
//
// It accepts submissions from trusted networks and forwards them to a
// smarthost, primarily Microsoft 365 via OAuth2. See MEMORY.md for the
// architecture and PROGRESS.md for the current implementation state.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	// Blank-imported so service.timezone works from a single binary: Windows
	// and minimal Linux images ship no IANA zoneinfo database on disk, and
	// this project builds no external runtime for one to live in.
	_ "time/tzdata"

	"github.com/tokajer/smtprelayd/internal/api"
	"github.com/tokajer/smtprelayd/internal/authms365"
	"github.com/tokajer/smtprelayd/internal/bounce"
	"github.com/tokajer/smtprelayd/internal/canary"
	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/delivery"
	"github.com/tokajer/smtprelayd/internal/listener"
	"github.com/tokajer/smtprelayd/internal/logging"
	"github.com/tokajer/smtprelayd/internal/metrics"
	"github.com/tokajer/smtprelayd/internal/selftest"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
	"github.com/tokajer/smtprelayd/internal/web"
)

// version is injected at build time via -ldflags.
var version = "dev"

const usage = `smtprelayd %s — Open Source SMTP Relay for Windows & Linux

usage: smtprelayd [-config <file>] [-out <file>] [-force] [-days N] [-scope read|admin] <command>

commands:
%s

Windows only, requires an elevated prompt:
%s

On Linux the service is managed with systemctl instead; the packaged unit
file registers it as smtprelayd.service.

smtprelayd is free software under the GNU GPL version 3 or later and comes
with absolutely no warranty. See the LICENSE file.
`

func main() {
	fs := flag.NewFlagSet("smtprelayd", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to the configuration file")
	console := fs.Bool("console", false, "also log to stderr when a log file is configured")
	outPath := fs.String("out", "", "output file for protect-secret (Windows only)")
	force := fs.Bool("force", false, "allow gen-cert to overwrite an existing certificate and key")
	days := fs.Int("days", 0, "validity in days for gen-cert (0 uses the default)")
	scope := fs.String("scope", "read", "scope for token new: read or admin")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, usage, version, commandList(false), commandList(true))
	}
	_ = fs.Parse(os.Args[1:])

	cmd := "run"
	if fs.NArg() > 0 {
		cmd = fs.Arg(0)
	}

	if earlyCommands()[cmd] {
		if err := controlService(cmd, *configPath); err != nil {
			fmt.Fprintln(os.Stderr, "smtprelayd:", err)
			os.Exit(1)
		}
		fmt.Printf("smtprelayd: %s ok\n", cmd)
		return
	}

	// A service started by the Windows SCM has no console and must go through
	// kardianos/service so Stop() is reachable; svc.IsWindowsService() is what
	// isWindowsService() reports on Windows and is always false elsewhere.
	if cmd == "run" && isWindowsService() {
		if err := runWindowsService(*configPath, *console); err != nil {
			fmt.Fprintln(os.Stderr, "smtprelayd:", err)
			os.Exit(1)
		}
		return
	}

	// "token new" is the one two-word command; the verb is checked here so
	// run keeps taking a single command string like every other path.
	if cmd == "token" {
		if fs.NArg() > 1 && fs.Arg(1) != "new" {
			fmt.Fprintf(os.Stderr, "smtprelayd: unknown token command %q, only \"new\" exists\n", fs.Arg(1))
			os.Exit(1)
		}
		// Anything past "token new" is a flag the parser already stopped
		// reading: Go's flag package ends at the first non-flag argument, so
		// "token new -scope admin" would silently issue a read token and the
		// operator would find out at the first 403. Refuse rather than
		// quietly do something other than what was asked.
		if fs.NArg() > 2 {
			trailing := strings.Join(fs.Args()[2:], " ")
			fmt.Fprintf(os.Stderr,
				"smtprelayd: %q came after the command, where flags are not read.\n"+
					"Put it first:  smtprelayd %s token new\n", trailing, trailing)
			os.Exit(1)
		}
	}

	if err := run(cmd, *configPath, *console, *outPath, *force, *days, *scope); err != nil {
		fmt.Fprintln(os.Stderr, "smtprelayd:", err)
		os.Exit(1)
	}
}

func run(cmd, configPath string, console bool, outPath string, force bool, days int, scope string) error {
	switch cmd {
	case "version":
		fmt.Println("smtprelayd", version)
		return nil

	case "secure-datadir":
		return secureDataDir(configPath)

	case "purge-datadir":
		return purgeDataDir(configPath)

	case "protect-secret":
		return protectSecret(outPath)

	case "token":
		return newToken(scope, os.Stdout)

	case "gen-cert":
		return genCert(configPath, force, days, os.Stdout)

	case "check":
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		if err := checkBind(cfg, os.Stdout); err != nil {
			return err
		}
		fmt.Printf("configuration OK: %d listener(s), %d client(s), %d route(s)\n",
			len(cfg.Listeners), len(cfg.Clients), len(cfg.Routes))
		return nil

	case "selftest":
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		notes, err := selftest.Run(cfg, 10*time.Second)
		for _, n := range notes {
			fmt.Println("note:", n)
		}
		if err != nil {
			return err
		}
		// A note means the probe never reached the relay decision on that
		// listener, so an unqualified pass would overstate what just
		// happened -- which is precisely what selftest.Run's contract says
		// the caller must not do.
		if len(notes) > 0 {
			fmt.Printf("open relay self-test found no open relay, but %d listener(s) were not exercised; see the note(s) above\n",
				len(notes))
			return nil
		}
		fmt.Println("open relay self-test passed")
		return nil

	case "run":
		return serve(context.Background(), configPath, console, nil)

	default:
		// knownCommand rather than a bare error: a command that is in the
		// table but not in this switch is a wiring mistake, and saying so is
		// more use than "unknown command" for something the help lists.
		if knownCommand(cmd) {
			return fmt.Errorf("command %q is documented but not wired up; this is a bug", cmd)
		}
		return fmt.Errorf("unknown command %q, see -h", cmd)
	}
}

// serve runs the relay until ctx is cancelled. The foreground and systemd
// paths pass context.Background(), relying solely on the signal.NotifyContext
// below; the Windows service path passes a context it cancels itself from
// Stop(), since a service has no process group to signal.
//
// ready, if non-nil, receives exactly one value: nil once every synchronous,
// fail-fast startup step has succeeded and only the long-running accept loop
// remains, or the error that made serve return if one occurred first.
// The foreground and systemd paths pass nil — a process that exits with a
// non-zero status is already a startup failure there, which is what systemd's
// Restart=on-failure acts on. On Windows nothing reads the process exit
// status: kardianos/service's Start must return quickly, and doing so
// unconditionally (the previous behaviour) told the SCM the service had
// started before config.Load, or any other step here, had even run — a bad
// configuration, a spool/store that would not open, a port already bound, or
// a rejected OAuth2 credential all went unnoticed by Windows, reaching only
// the log file. winProgram.Start (service_windows.go) now blocks on ready and
// forwards a startup error to the SCM instead.
func serve(ctx context.Context, configPath string, console bool, ready chan<- error) (err error) {
	notified := false
	notifyReady := func(e error) {
		if ready == nil || notified {
			return
		}
		notified = true
		ready <- e
	}
	defer func() { notifyReady(err) }()

	cfg, err := config.Load(configPath)
	if err != nil {
		logStartupFailure(configPath, cfg, err)
		return err
	}
	if err := checkEnvironment(cfg); err != nil {
		return err
	}

	log, closer, err := openLog(cfg, console)
	if err != nil {
		return err
	}
	defer closer.Close()

	// From here on the logger is live and writable, so every startup failure
	// is logged before it is returned: main() only echoes it to stderr (lost
	// on a Windows service with no console), while the log file is what an
	// operator actually checks afterward.
	sp, err := openSpool(cfg)
	if err != nil {
		log.Error("spool: failed to open", "error", err)
		return err
	}
	st, err := store.Open(cfg.Service.DataDir, log, cfg.History.RetentionDays, cfg.History.RetainSubjects)
	if err != nil {
		log.Error("store: failed to open", "error", err)
		return err
	}
	defer st.Close()

	log.Info("starting", "version", version, "config", cfg.Path,
		"data_dir", cfg.Service.DataDir, "queued", sp.Len())

	// The registry is built here, ahead of everything that feeds it, and
	// handed down: the listener counts session panics and journal failures
	// into it, the delivery manager its outcomes, and the dashboard, the API
	// and the metrics endpoint read it. It used to be built inside
	// delivery.New and pulled back out through a getter, which hid the
	// composition in a worker and left the listener with nothing to count on.
	reg := metrics.New(metrics.ConfigExpiry(cfg), sp, routeNames(cfg), canaryNames(cfg), nil)

	set, err := listener.New(cfg, sp, log, st, reg)
	if err != nil {
		log.Error("listener: failed to start", "error", err)
		return err
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Every background goroutine below holds the store, and web.Serve drains
	// in-flight dashboard requests for up to five seconds. Deferred calls run
	// LIFO, so cancelling and waiting has to happen here, after the defers
	// that opened the store: this one runs before them and leaves st.Close()
	// with nothing still reading from it. stop() is called inside rather than
	// relied on from its own defer for the same reason -- a startup error
	// returning early must cancel the context before anything waits on it.
	var bg sync.WaitGroup
	defer func() {
		stop()
		bg.Wait()
	}()

	notifier := bounce.New(cfg, sp, st, log)
	dm, err := delivery.New(cfg, sp, log, st, reg, notifier)
	if err != nil {
		log.Error("delivery: failed to start", "error", err)
		return err
	}
	if err := verifyTokens(ctx, dm, log); err != nil {
		return err
	}
	done := startWorkers(ctx, &bg, cfg, sp, st, log, dm, notifier)

	// Both HTTP sockets are bound here, synchronously, for the reason
	// set.Bind is separate from set.Run: a port already in use used to be a
	// log line from a goroutine after the service had reported itself
	// started, and on Windows the SCM then showed a running service with no
	// dashboard.
	if err := startHTTP(ctx, &bg, cfg, st, sp, reg, log); err != nil {
		return err
	}

	if err := set.Bind(); err != nil {
		log.Error("listener: failed to bind", "error", err)
		return err
	}
	// Everything that can fail synchronously has now succeeded; only the
	// accept loop, which runs until shutdown, remains.
	notifyReady(nil)
	set.Run(ctx)
	// Not shutdown synchronisation -- the deferred bg.Wait above is that, on
	// every return path. This waits only so that the count below is taken
	// after the delivery manager has stopped draining the spool, rather than
	// reporting a queue length that was already stale when it was read.
	<-done
	log.Info("stopped", "queued", sp.Len())
	return nil
}

// logStartupFailure makes a best-effort attempt to also put a config.Load
// failure into <data_dir>/smtprelayd-error.log. Without this, a
// configuration that fails validation (a typo'd service.timezone, say) is
// reported correctly by `check` on stdout, but `run` failing the same check
// left nothing behind except stderr — invisible on a Windows service with no
// console, and easy to miss in journalctl too.
//
// A fixed filename rather than cfg.Log.File is deliberate: the configuration
// that just failed to validate is exactly the one value that cannot be
// trusted to name its own error log. Nothing is written unless
// checkEnvironment first proves the data directory is safe to write into —
// config.Load failing is precisely the case where that has not been checked
// yet, so this must run its own gate rather than assume one already ran.
func logStartupFailure(configPath string, cfg *config.Config, cause error) {
	if cfg == nil || cfg.Service.DataDir == "" {
		return
	}
	if err := os.MkdirAll(cfg.Service.DataDir, 0o700); err != nil {
		return
	}
	// Deliberately a narrower gate than checkEnvironment's. CheckDir is the
	// half that stops this write being redirected: a symlink or reparse
	// point, or a path that is not a directory. The data directory ACL check
	// is the other half, and what that one protects is the confidentiality of
	// message data -- queue IDs, senders, recipients -- which the operational
	// log carries and this file does not. This file holds the configuration
	// path and the validation error that stopped startup.
	//
	// Running the full gate here defeated the purpose on Windows: before the
	// installer's secure-datadir has run, the directory still inherits its
	// DACL, so a service that failed to start produced no console (it is a
	// service) and no error log either -- exactly the case this exists for,
	// and exactly the state the 2026-08-11 field incident was in.
	if err := config.CheckDir(cfg.Service.DataDir); err != nil {
		return
	}
	path := filepath.Join(cfg.Service.DataDir, "smtprelayd-error.log")
	log, closer, err := logging.New(logging.Options{File: path})
	if err != nil {
		return
	}
	defer closer.Close()
	log.Error("startup failed", "config", configPath, "error", cause)
}

// checkEnvironment refuses to start when the data directory or the directory
// holding the binary could be modified by an unprivileged local user. Each of
// those turns a local account into control of a privileged process, so this
// aborts rather than warns.
func checkEnvironment(cfg *config.Config) error {
	if err := os.MkdirAll(cfg.Service.DataDir, 0o700); err != nil {
		return err
	}
	if err := config.CheckDir(cfg.Service.DataDir); err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	if err := verifyDataDirSecurity(cfg.Service.DataDir); err != nil {
		return fmt.Errorf("data directory ACL: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := config.CheckDir(filepath.Dir(exe)); err != nil {
		return fmt.Errorf("binary directory: %w", err)
	}
	return nil
}

// verifyTokens fetches an OAuth2 token for every xoauth2 route at startup
// and decides whether a failure is fatal.
//
// Only a rejection the token endpoint itself issued is: the credentials are
// wrong and no retry changes that. An endpoint that cannot be reached is a
// different matter -- refusing to bind the listeners while Microsoft is down
// turns a delivery outage into an acceptance outage, and the devices this
// relay serves do not queue. Mail is then accepted into the spool and the
// token is fetched again at the first delivery attempt. Decided 2026-08-21,
// narrowed 2026-09-18; see MEMORY.md.
func verifyTokens(ctx context.Context, dm *delivery.Manager, log *slog.Logger) error {
	err := dm.VerifyTokens(ctx)
	if err == nil {
		return nil
	}
	var cred *authms365.CredentialError
	if errors.As(err, &cred) {
		log.Error("delivery: startup oauth2 token verification failed, the credentials were rejected", "error", err)
		return err
	}
	log.Warn("delivery: startup oauth2 token verification could not reach the token endpoint; "+
		"starting anyway, deliveries retry it", "error", err)
	return nil
}

// openLog resolves the logging configuration and builds the process logger.
// Every value it reads was already validated by config.Load; reaching an
// error here means the file changed underneath us, which is not a case to
// paper over.
func openLog(cfg *config.Config, console bool) (*slog.Logger, io.Closer, error) {
	level, err := config.ParseLevel(cfg.Service.LogLevel)
	if err != nil {
		return nil, nil, err
	}
	logFile, err := config.LogPath(cfg.Service.DataDir, cfg.Log.File)
	if err != nil {
		return nil, nil, err
	}
	loc, err := config.ParseTimezone(cfg.Service.Timezone)
	if err != nil {
		return nil, nil, err
	}
	return logging.New(logging.Options{
		Level:      level,
		File:       logFile,
		Console:    console,
		MaxSizeMB:  cfg.Log.MaxSizeMB,
		MaxBackups: cfg.Log.MaxBackups,
		MaxAgeDays: cfg.Log.MaxAgeDays,
		Location:   loc,
	})
}

// openSpool opens the queue directory and applies the configured quota and
// failed-message retention.
func openSpool(cfg *config.Config) (*spool.Spool, error) {
	sp, err := spool.Open(cfg.Service.DataDir)
	if err != nil {
		return nil, err
	}
	sp.SetQuota(cfg.Limits.SpoolMaxGB, cfg.Limits.SpoolWarnPercent)
	sp.SetFailedRetention(time.Duration(cfg.Queue.FailedRetentionHours) * time.Hour)
	return sp, nil
}

// startWorkers launches every background goroutine that drains or watches
// the spool, and returns a channel closed once the delivery manager has
// stopped. The caller waits on it only to take an accurate final queue
// count; shutdown itself is bg.Wait.
func startWorkers(ctx context.Context, bg *sync.WaitGroup, cfg *config.Config,
	sp *spool.Spool, st *store.Store, log *slog.Logger,
	dm *delivery.Manager, notifier *bounce.Notifier) <-chan struct{} {
	done := make(chan struct{})
	bg.Go(func() {
		dm.Run(ctx)
		close(done)
	})
	bg.Go(func() { notifier.Run(ctx) })
	lifetime := time.Duration(cfg.Queue.MaxLifetimeHours) * time.Hour
	for _, c := range cfg.Canaries {
		r := canary.New(c, cfg.Service.Hostname, lifetime, sp, st, log)
		bg.Go(func() { r.Run(ctx) })
	}
	// Started unconditionally: it reports through the notifier, which
	// declines to send when bounce.notify is empty, so an unconfigured
	// contact costs one idle ticker rather than needing a switch of its own.
	expiryWatcher := bounce.NewExpiryWatcher(cfg, notifier, log)
	bg.Go(func() { expiryWatcher.Run(ctx) })
	return done
}

// startHTTP binds and serves the metrics endpoint and the dashboard, each
// only if enabled. Binding happens here, synchronously, so that an address
// already in use fails startup instead of being logged from a goroutine
// after the service has reported itself started.
func startHTTP(ctx context.Context, bg *sync.WaitGroup, cfg *config.Config,
	st *store.Store, sp *spool.Spool, reg *metrics.Registry, log *slog.Logger) error {
	if cfg.Metrics.Enabled {
		ln, err := metrics.Listen(cfg)
		if err != nil {
			log.Error("metrics: failed to bind", "error", err)
			return err
		}
		bg.Go(func() {
			if err := metrics.Serve(ctx, cfg, ln, reg, log); err != nil {
				log.Error("metrics listener stopped", "error", err)
			}
		})
	}
	if !cfg.Web.Enabled {
		return nil
	}

	ws, err := web.New(cfg, st, sp, reg, version, log)
	if err != nil {
		log.Error("web: failed to start", "error", err)
		return err
	}
	as := api.New(cfg, st, sp, reg, version, log)

	// The dashboard and the JSON API share one listener, per
	// docs/dev/PHASE4-PLAN.md: the api handler is mounted under /api/v1/
	// with that prefix stripped, so its own routes are registered without
	// it, and everything else falls through to the dashboard.
	mux := http.NewServeMux()
	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", as.Handler()))
	mux.Handle("/", ws.Handler())

	ln, err := web.Listen(cfg)
	if err != nil {
		log.Error("web: failed to bind", "error", err)
		return err
	}
	bg.Go(func() {
		if err := web.Serve(ctx, ln, mux, log); err != nil {
			log.Error("web listener stopped", "error", err)
		}
	})
	return nil
}

// routeNames and canaryNames are what the metrics registry is seeded with,
// so a route or canary that has not delivered yet still reports zero.
func routeNames(cfg *config.Config) []string {
	out := make([]string, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		out = append(out, r.Name)
	}
	return out
}

func canaryNames(cfg *config.Config) []string {
	out := make([]string, 0, len(cfg.Canaries))
	for _, c := range cfg.Canaries {
		out = append(out, c.Name)
	}
	return out
}

func defaultConfigPath() string {
	if p := os.Getenv("SMTPRELAYD_CONFIG"); p != "" {
		return p
	}
	if os.PathSeparator == '\\' {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "SMTPRelayd", "smtprelayd.toml")
	}
	return "/etc/smtprelayd/smtprelayd.toml"
}
