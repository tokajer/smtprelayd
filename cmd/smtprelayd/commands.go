// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package main

import (
	"fmt"
	"strings"
)

// command is one entry of the command set: the word an operator types, the
// help text it gets, and where it is handled.
//
// The set used to be three independent lists -- the usage text, the early
// switch in main for the Windows service-control verbs, and the switch in
// run. Answering "which commands exist" meant reading all three and
// comparing, and a command added to one and forgotten in another is silent:
// documented but unreachable, or reachable but undocumented.
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

	// early marks a command main handles before run is reached, because it
	// needs the service control path rather than the ordinary one. It is
	// still listed here so that the set stays in one place.
	early bool
}

// commands is the whole command set, in the order the usage text lists it.
var commands = []command{
	{name: "run", help: []string{"start the relay in the foreground (default)"}},
	{name: "check", help: []string{"validate the configuration and its bind addresses, then exit"}},
	{name: "selftest", help: []string{"attempt to relay through the running instance and fail if it works"}},
	{name: "gen-cert", help: []string{
		"write a self-signed certificate and key to the paths [tls]",
		"cert_file and key_file already name, for an internal listener",
		"with no CA behind it; refuses to overwrite either file unless",
		"-force is given, and -days N sets a validity other than the",
		"default (flags must come before the command, like -config)",
	}},
	{name: "token new", help: []string{
		"generate an API token, print it once, and print the",
		"[[web.token]] block to paste into the configuration; -scope",
		"selects read (default) or admin",
	}},
	{name: "version", help: []string{"print the version and exit"}},

	{name: "install", windows: true, early: true, help: []string{`register as a Windows service (runs as NT SERVICE\smtprelayd)`}},
	{name: "uninstall", windows: true, early: true, help: []string{"remove the Windows service"}},
	{name: "start", windows: true, early: true, help: []string{"start the registered Windows service"}},
	{name: "stop", windows: true, early: true, help: []string{"stop the registered Windows service"}},
	{name: "secure-datadir", windows: true, help: []string{"write the data directory ACL the service requires to start"}},
	{name: "purge-datadir", windows: true, help: []string{
		"delete the data directory (spool and history); run by the",
		`MSI only when the uninstall dialog is answered "yes"`,
	}},
	{name: "protect-secret", windows: true, help: []string{
		"encrypt a secret with this machine's DPAPI key and write it",
		"to -out (flag must come before the command, like -config),",
		"for a dpapi:<path> reference in the configuration; reads",
		"the plaintext secret as a single line from stdin, e.g.:",
		`smtprelayd -out C:\ProgramData\SMTPRelayd\secret.bin protect-secret`,
	}},
}

// verb is the single word run dispatches on. "token new" is the one two-word
// command; main checks the second word and run sees "token".
func (c command) verb() string {
	if i := strings.IndexByte(c.name, ' '); i >= 0 {
		return c.name[:i]
	}
	return c.name
}

// earlyCommands are the verbs main handles before run, as a set.
func earlyCommands() map[string]bool {
	out := map[string]bool{}
	for _, c := range commands {
		if c.early {
			out[c.verb()] = true
		}
	}
	return out
}

// knownCommand reports whether verb is in the command set at all, so an
// unknown one can be refused with the same message wherever it is noticed.
func knownCommand(verb string) bool {
	for _, c := range commands {
		if c.verb() == verb {
			return true
		}
	}
	return false
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
