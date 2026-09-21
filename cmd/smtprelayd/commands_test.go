// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package main

import (
	"strings"
	"testing"
)

// Dispatch is a table lookup, so "documented" and "reachable" are one fact --
// but only as long as every entry actually carries a handler. This is the
// assertion that replaced run's runtime "documented but not wired up; this is
// a bug" branch: a missing handler is now a test failure rather than an error
// an operator discovers.
func TestEveryCommandHasAHandler(t *testing.T) {
	for _, c := range commands {
		if c.handler == nil {
			t.Errorf("%q is in the usage text with no handler, so it would panic on dispatch", c.name)
		}
	}
}

// And the handler has to be reached. The set used to live in three places --
// the usage text, the early switch in main, and the switch in run -- with
// nothing tying them together, so a command added to one and forgotten in
// another was silent: listed in the help and answered with "unknown command",
// or reachable and undocumented.
//
// run is given a configuration path that does not exist, so a command that is
// wired up fails on the configuration or does its work; what this asserts is
// only that none of them falls through to the unknown-command branch.
func TestEveryDocumentedCommandIsWiredUp(t *testing.T) {
	opts := cmdOptions{configPath: "/nonexistent/smtprelayd.toml", scope: "read"}
	for _, c := range commands {
		if c.controlsService {
			// Registering, starting or stopping a Windows service is not
			// something this test may do as a side effect when it runs on
			// Windows. TestEveryCommandHasAHandler covers these four.
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			verb := c.verb()
			err := run(verb, opts)
			if err == nil {
				return // did its work without needing the configuration
			}
			if strings.Contains(err.Error(), "unknown command") {
				t.Errorf("%q is in the usage text but is not in the command table", verb)
			}
		})
	}
}

// And the reverse: a word that is not in the table is refused, rather than
// silently doing nothing.
func TestAnUnknownCommandIsRefused(t *testing.T) {
	err := run("definitely-not-a-command", cmdOptions{configPath: "/nonexistent/smtprelayd.toml", scope: "read"})
	if err == nil {
		t.Fatal("an unknown command was accepted")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("refused with %v, want the unknown-command message", err)
	}
}

// The usage text is rendered from the table, so the two cannot drift. This
// pins the shape the rendering has to keep: every command listed once, under
// the right heading, with its description aligned after the longest name.
// entryNames extracts the command names a rendered section lists. Matching on
// substrings does not work here: the names are ordinary words -- "run",
// "start", "check" -- and they occur inside other commands' descriptions.
// Only a line that starts an entry names a command.
func entryNames(section string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue // blank, or a continuation line indented further
		}
		name, _, found := strings.Cut(strings.TrimLeft(line, " "), "  ")
		if found {
			out[name] = true
		}
	}
	return out
}

// The usage text is rendered from the table, so the two cannot drift. This
// pins the shape the rendering has to keep: every command listed once, under
// the right heading, with its description aligned after the longest name.
func TestUsageListsEveryCommandUnderTheRightHeading(t *testing.T) {
	general, windows := entryNames(commandList(false)), entryNames(commandList(true))
	for _, c := range commands {
		in, out, heading := general, windows, "general"
		if c.windows {
			in, out, heading = windows, general, "Windows-only"
		}
		if !in[c.name] {
			t.Errorf("%q is missing from the %s section", c.name, heading)
		}
		if out[c.name] {
			t.Errorf("%q is listed in both sections", c.name)
		}
	}
	if got, want := len(general)+len(windows), len(commands); got != want {
		t.Errorf("the usage lists %d commands, the table holds %d", got, want)
	}

	// Alignment: within a section every description starts in the same
	// column, which is what makes the block readable when a longer command
	// is added.
	for name, section := range map[string]string{"general": commandList(false), "windows": commandList(true)} {
		col := -1
		for _, line := range strings.Split(section, "\n") {
			if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
				continue
			}
			cmdName, desc, found := strings.Cut(strings.TrimLeft(line, " "), "  ")
			if !found {
				continue
			}
			start := strings.Index(line, strings.TrimLeft(desc, " "))
			if col == -1 {
				col = start
			} else if start != col {
				t.Errorf("%s: %q starts its description at column %d, others at %d", name, cmdName, start, col)
			}
		}
	}
}
