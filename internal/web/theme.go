// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tokajer/smtprelayd/internal/config"
)

// themeOverrides renders the operator's [web.theme] colours as a CSS block
// appended to the embedded stylesheet, which declares the same custom
// properties with the built-in values first. Two properties of this matter:
//
// Every value passes config.IsHexColor again here. internal/config already
// rejects anything else at load time, so this is the second of two
// independent reasons a theme value can never close its declaration and open
// a rule of its own — the same doubled-check shape the config view uses for
// secrets. A value that somehow arrives invalid is dropped, not escaped:
// there is no correct rendering of a colour that is not one.
//
// The selector repeats the two scheme selectors the stylesheet uses, so the
// override has at least their specificity and, coming later in the file,
// wins in the light scheme and the dark one alike. That is deliberate: an
// override is a decision about how the dashboard looks, not a light-mode
// default the dark scheme is free to overrule.
func themeOverrides(t config.Theme) string {
	colors := t.Colors()
	names := make([]string, 0, len(colors))
	for name, v := range colors {
		if config.IsHexColor(v) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("\n/* [web.theme] overrides */\n")
	b.WriteString(`:root, :root[data-theme="light"], :root[data-theme="dark"] {` + "\n")
	for _, name := range names {
		fmt.Fprintf(&b, "\t%s: %s;\n", name, colors[name])
	}
	b.WriteString("}\n")
	return b.String()
}

// themeMode is the value of the document's data-theme attribute. The
// stylesheet keys its dark scheme off prefers-color-scheme unless this pins
// one, which is how the dashboard follows or ignores the operating system
// without a line of JavaScript.
func themeMode(t config.Theme) string {
	switch t.Mode {
	case "light", "dark":
		return t.Mode
	default:
		return "auto"
	}
}
