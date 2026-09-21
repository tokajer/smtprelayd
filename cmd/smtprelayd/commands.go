// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/selftest"
)

// cmdOptions is what the flags contributed, handed to whichever command runs.
//
// One value rather than a parameter list: every handler in the table takes
// the same thing, so a command that needs a new flag adds a field here rather
// than a parameter to every handler signature and to run itself.
type cmdOptions struct {
	configPath string
	console    bool
	outPath    string
	force      bool
	days       int
	scope      string
}

// command is one entry of the command set: the word an operator types, the
// help text it gets, and the function that carries it out.
//
// The set used to be three independent lists -- the usage text, the early
// switch in main for the Windows service-control verbs, and the switch in
// run. Answering "which commands exist" meant reading all three and
// comparing, and a command added to one and forgotten in another is silent:
// documented but unreachable, or reachable but undocumented.
//
// handler is what closed the last of the three. Until 2026-09-21 this struct
// carried the name, the help and two flags but not the function, so run kept
// its own switch and a command in the table with no case there was caught at
// runtime by a "documented but not wired up; this is a bug" error. It is the
// shape internal/web's dashboardPages already used, which needs no such
// guard: with the handler in the table there is no second list to disagree
// with.
type command struct {
	name string

	// help is the description as it appears under the command in the usage
	// text, already wrapped. The first line follows the name on the same
	// line; any further lines are indented to match.
	help []string

	// windows marks a command listed under the elevated-prompt section. It
	// affects only where the usage text prints it: the handlers themselves
	// are built per platform, so a Windows-only command on Linux reaches a
	// stub that says so.
	windows bool

	// controlsService marks a command that talks to the Windows service
	// manager rather than doing work in this process. It changes nothing
	// about dispatch -- run reaches these through handler like every other
	// command -- and exists so that the test which invokes every documented
	// command to prove it is wired up skips exactly these four. Registering,
	// starting or stopping a service is not something a test run on Windows
	// may do as a side effect.
	controlsService bool

	// handler carries the command out. Every entry sets it; there is no
	// nil case to guard, and TestEveryCommandHasAHandler is what keeps that
	// true.
	handler func(cmdOptions) error
}

// commands is the whole command set, in the order the usage text lists it.
var commands = []command{
	{name: "run", help: []string{"start the relay in the foreground (default)"},
		handler: func(o cmdOptions) error {
			return serve(context.Background(), o.configPath, o.console, nil)
		}},
	{name: "check", help: []string{"validate the configuration and its bind addresses, then exit"},
		handler: cmdCheck},
	{name: "selftest", help: []string{"attempt to relay through the running instance and fail if it works"},
		handler: cmdSelftest},
	{name: "gen-cert", help: []string{
		"write a self-signed certificate and key to the paths [tls]",
		"cert_file and key_file already name, for an internal listener",
		"with no CA behind it; refuses to overwrite either file unless",
		"-force is given, and -days N sets a validity other than the",
		"default (flags must come before the command, like -config)",
	}, handler: func(o cmdOptions) error { return genCert(o.configPath, o.force, o.days, os.Stdout) }},
	{name: "token new", help: []string{
		"generate an API token, print it once, and print the",
		"[[web.token]] block to paste into the configuration; -scope",
		"selects read (default) or admin",
	}, handler: func(o cmdOptions) error { return newToken(o.scope, os.Stdout) }},
	{name: "version", help: []string{"print the version and exit"},
		handler: func(cmdOptions) error { fmt.Println("smtprelayd", version); return nil }},

	{name: "install", windows: true, controlsService: true, handler: serviceControl("install"),
		help: []string{`register as a Windows service (runs as NT SERVICE\smtprelayd)`}},
	{name: "uninstall", windows: true, controlsService: true, handler: serviceControl("uninstall"),
		help: []string{"remove the Windows service"}},
	{name: "start", windows: true, controlsService: true, handler: serviceControl("start"),
		help: []string{"start the registered Windows service"}},
	{name: "stop", windows: true, controlsService: true, handler: serviceControl("stop"),
		help: []string{"stop the registered Windows service"}},
	{name: "secure-datadir", windows: true, help: []string{"write the data directory ACL the service requires to start"},
		handler: func(o cmdOptions) error { return secureDataDir(o.configPath) }},
	{name: "purge-datadir", windows: true, help: []string{
		"delete the data directory (spool and history); run by the",
		`MSI only when the uninstall dialog is answered "yes"`,
	}, handler: func(o cmdOptions) error { return purgeDataDir(o.configPath) }},
	{name: "protect-secret", windows: true, help: []string{
		"encrypt a secret with this machine's DPAPI key and write it",
		"to -out (flag must come before the command, like -config),",
		"for a dpapi:<path> reference in the configuration; reads",
		"the plaintext secret as a single line from stdin, e.g.:",
		`smtprelayd -out C:\ProgramData\SMTPRelayd\secret.bin protect-secret`,
	}, handler: func(o cmdOptions) error { return protectSecret(o.outPath) }},
}

// serviceControl builds the handler for one of the four service-manager
// verbs. They differ only in the word they pass on, and the success line is
// the one main used to print for all of them before these had handlers of
// their own.
func serviceControl(name string) func(cmdOptions) error {
	return func(o cmdOptions) error {
		if err := controlService(name, o.configPath); err != nil {
			return err
		}
		fmt.Printf("smtprelayd: %s ok\n", name)
		return nil
	}
}

// cmdCheck validates the configuration and every address it would bind.
func cmdCheck(o cmdOptions) error {
	cfg, err := config.Load(o.configPath)
	if err != nil {
		return err
	}
	if err := checkBind(cfg, os.Stdout); err != nil {
		return err
	}
	fmt.Printf("configuration OK: %d listener(s), %d client(s), %d route(s)\n",
		len(cfg.Listeners), len(cfg.Clients), len(cfg.Routes))
	return nil
}

// cmdSelftest attempts to relay through the running instance and fails if it
// works.
func cmdSelftest(o cmdOptions) error {
	cfg, err := config.Load(o.configPath)
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
	// listener, so an unqualified pass would overstate what just happened --
	// which is precisely what selftest.Run's contract says the caller must
	// not do.
	if len(notes) > 0 {
		fmt.Printf("open relay self-test found no open relay, but %d listener(s) were not exercised; see the note(s) above\n",
			len(notes))
		return nil
	}
	fmt.Println("open relay self-test passed")
	return nil
}

// verb is the single word run dispatches on. "token new" is the one two-word
// command; main checks the second word and run sees "token".
func (c command) verb() string {
	if i := strings.IndexByte(c.name, ' '); i >= 0 {
		return c.name[:i]
	}
	return c.name
}

// lookupCommand finds the entry a verb names. It is the whole of dispatch:
// run looks the verb up and calls what it finds, so "documented" and
// "reachable" are the same fact rather than two lists that have to agree.
func lookupCommand(verb string) (command, bool) {
	for _, c := range commands {
		if c.verb() == verb {
			return c, true
		}
	}
	return command{}, false
}

// commandList renders one section of the usage text. The column the
// descriptions start in is computed from the longest name in that section, so
// adding a longer command cannot leave the block ragged.
func commandList(windows bool) string {
	width := 0
	for _, c := range commands {
		if c.windows == windows && len(c.name) > width {
			width = len(c.name)
		}
	}

	var b strings.Builder
	for _, c := range commands {
		if c.windows != windows {
			continue
		}
		indent := strings.Repeat(" ", 2+width+2)
		for i, line := range c.help {
			if i == 0 {
				fmt.Fprintf(&b, "  %-*s  %s\n", width, c.name, line)
				continue
			}
			fmt.Fprintf(&b, "%s%s\n", indent, line)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}
