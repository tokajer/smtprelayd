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
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/delivery"
	"github.com/tokajer/smtprelayd/internal/listener"
	"github.com/tokajer/smtprelayd/internal/logging"
	"github.com/tokajer/smtprelayd/internal/selftest"
	"github.com/tokajer/smtprelayd/internal/spool"
)

// version is injected at build time via -ldflags.
var version = "dev"

const usage = `smtprelayd %s — Open Source SMTP Relay for Windows & Linux

usage: smtprelayd [-config <file>] <command>

commands:
  run        start the relay in the foreground (default)
  check      load and validate the configuration, then exit
  selftest   attempt to relay through the running instance and fail if it works
  version    print the version and exit

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

	case "check":
		cfg, err := config.Load(configPath)
		if err != nil {
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
		return serve(configPath, console)

	default:
		return fmt.Errorf("unknown command %q, see -h", cmd)
	}
}

func serve(configPath string, console bool) error {
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
	logFile := ""
	if cfg.Log.File != "" {
		logFile = filepath.Join(cfg.Service.DataDir, cfg.Log.File)
	}
	log, closer, err := logging.New(logging.Options{Level: level, File: logFile, Console: console})
	if err != nil {
		return err
	}
	defer closer.Close()

	sp, err := spool.Open(cfg.Service.DataDir)
	if err != nil {
		return err
	}
	log.Info("starting", "version", version, "config", cfg.Path,
		"data_dir", cfg.Service.DataDir, "queued", sp.Len())

	set, err := listener.New(cfg, sp, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dm, err := delivery.New(cfg, sp, log)
	if err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		dm.Run(ctx)
		close(done)
	}()

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
