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
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tokajer/smtprelayd/internal/api"
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

usage: smtprelayd [-config <file>] <command>

commands:
  run        start the relay in the foreground (default)
  check      validate the configuration and its bind addresses, then exit
  selftest   attempt to relay through the running instance and fail if it works
  version    print the version and exit

Windows only, requires an elevated prompt:
  install         register as a Windows service (runs as NT SERVICE\smtprelayd)
  uninstall       remove the Windows service
  start           start the registered Windows service
  stop            stop the registered Windows service
  secure-datadir  write the data directory ACL the service requires to start

On Linux the service is managed with systemctl instead; the packaged unit
file registers it as smtprelayd.service.

smtprelayd is free software under the GNU GPL version 3 or later and comes
with absolutely no warranty. See the LICENSE file.
`

func main() {
	fs := flag.NewFlagSet("smtprelayd", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath(), "path to the configuration file")
	console := fs.Bool("console", false, "also log to stderr when a log file is configured")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	_ = fs.Parse(os.Args[1:])

	cmd := "run"
	if fs.NArg() > 0 {
		cmd = fs.Arg(0)
	}

	switch cmd {
	case "install", "uninstall", "start", "stop":
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

	if err := run(cmd, *configPath, *console); err != nil {
		fmt.Fprintln(os.Stderr, "smtprelayd:", err)
		os.Exit(1)
	}
}

func run(cmd, configPath string, console bool) error {
	switch cmd {
	case "version":
		fmt.Println("smtprelayd", version)
		return nil

	case "secure-datadir":
		return secureDataDir(configPath)

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
		if err := selftest.Run(cfg, 10*time.Second); err != nil {
			return err
		}
		fmt.Println("open relay self-test passed")
		return nil

	case "run":
		return serve(context.Background(), configPath, console)

	default:
		return fmt.Errorf("unknown command %q, see -h", cmd)
	}
}

// serve runs the relay until ctx is cancelled. The foreground and systemd
// paths pass context.Background(), relying solely on the signal.NotifyContext
// below; the Windows service path passes a context it cancels itself from
// Stop(), since a service has no process group to signal.
func serve(ctx context.Context, configPath string, console bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if err := checkEnvironment(cfg); err != nil {
		return err
	}

	level, err := config.ParseLevel(cfg.Service.LogLevel)
	if err != nil {
		return err
	}
	logFile, err := config.LogPath(cfg.Service.DataDir, cfg.Log.File)
	if err != nil {
		// Load has already validated this; reaching here means the value
		// changed underneath us, which is not a case to paper over.
		return err
	}
	log, closer, err := logging.New(logging.Options{
		Level:      level,
		File:       logFile,
		Console:    console,
		MaxSizeMB:  cfg.Log.MaxSizeMB,
		MaxBackups: cfg.Log.MaxBackups,
		MaxAgeDays: cfg.Log.MaxAgeDays,
	})
	if err != nil {
		return err
	}
	defer closer.Close()

	sp, err := spool.Open(cfg.Service.DataDir)
	if err != nil {
		return err
	}
	sp.SetQuota(cfg.Limits.SpoolMaxGB, cfg.Limits.SpoolWarnPercent)
	sp.SetFailedRetention(time.Duration(cfg.Queue.FailedRetentionHours) * time.Hour)

	st, err := store.Open(cfg.Service.DataDir, log, cfg.History.RetentionDays, cfg.History.RetainSubjects)
	if err != nil {
		return err
	}
	defer st.Close()

	log.Info("starting", "version", version, "config", cfg.Path,
		"data_dir", cfg.Service.DataDir, "queued", sp.Len())

	set, err := listener.New(cfg, sp, log, st)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	dm, err := delivery.New(cfg, sp, log, st)
	if err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		dm.Run(ctx)
		close(done)
	}()
	go dm.Notifier().Run(ctx)

	if cfg.Metrics.Enabled {
		go func() {
			if err := metrics.Serve(ctx, cfg, dm.Metrics(), log); err != nil {
				log.Error("metrics listener stopped", "error", err)
			}
		}()
	}

	if cfg.Web.Enabled {
		ws, err := web.New(cfg, st, sp, dm.Metrics(), version, log)
		if err != nil {
			return err
		}
		as := api.New(cfg, st, sp, dm.Metrics(), version, log)

		// The dashboard and the JSON API share one listener, per
		// docs/PHASE4-PLAN.md: the api handler is mounted under /api/v1/
		// with that prefix stripped, so its own routes are registered
		// without it, and everything else falls through to the dashboard.
		mux := http.NewServeMux()
		mux.Handle("/api/v1/", http.StripPrefix("/api/v1", as.Handler()))
		mux.Handle("/", ws.Handler())

		go func() {
			if err := web.Serve(ctx, cfg, mux, log); err != nil {
				log.Error("web listener stopped", "error", err)
			}
		}()
	}

	if err := set.Serve(ctx); err != nil {
		stop()
		<-done
		return err
	}
	<-done
	log.Info("stopped", "queued", sp.Len())
	return nil
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
