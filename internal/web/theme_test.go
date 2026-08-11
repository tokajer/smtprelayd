// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/tokajer/smtprelayd/internal/config"
)

func TestThemeOverridesAreAppendedToTheStylesheet(t *testing.T) {
	cfg := testConfig(t, `
[web.theme]
mode   = "dark"
accent = "#7c4dff"
text   = "#eeeeee"
`)
	srv, _, _ := testServer(t, cfg)
	rec := get(t, srv.Handler(), "/static/style.css")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	css := rec.Body.String()
	base := strings.Index(css, "--accent: #2f5fa8")
	override := strings.Index(css, "--accent: #7c4dff")
	if base < 0 || override < 0 {
		t.Fatalf("built-in value or override missing from stylesheet:\n%s", css)
	}
	if override < base {
		t.Fatal("override block precedes the built-in declaration; it would not win")
	}
	if !strings.Contains(css, "--text: #eeeeee") {
		t.Error("second override missing")
	}
	if !strings.Contains(css, `:root[data-theme="dark"] {`) {
		t.Error("override selector does not match the dark scheme selector's specificity")
	}
}

// A value that is not a hex colour cannot reach the stylesheet even if it
// bypasses the loader's validation, which is the point of checking twice.
func TestThemeOverridesDropUnvalidatedValues(t *testing.T) {
	css := themeOverrides(config.Theme{
		Accent: "#fff; } body { display: none",
		Text:   "#123456",
	})
	if strings.Contains(css, "display: none") || strings.Contains(css, "--accent") {
		t.Fatalf("an invalid colour reached the stylesheet:\n%s", css)
	}
	if !strings.Contains(css, "--text: #123456") {
		t.Fatalf("the valid colour beside it was dropped too:\n%s", css)
	}
}

func TestNoThemeMeansNoOverrideBlock(t *testing.T) {
	if got := themeOverrides(config.Theme{Mode: "dark"}); got != "" {
		t.Fatalf("themeOverrides() = %q, want empty", got)
	}
}

func TestThemeModePinsTheDocumentScheme(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"", `data-theme="auto"`},
		{"auto", `data-theme="auto"`},
		{"light", `data-theme="light"`},
		{"dark", `data-theme="dark"`},
	} {
		extra := ""
		if tc.mode != "" {
			extra = "\n[web.theme]\nmode = \"" + tc.mode + "\"\n"
		}
		cfg := testConfig(t, extra)
		srv, _, _ := testServer(t, cfg)
		rec := get(t, srv.Handler(), "/queue")
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("mode %q: %s missing from the rendered page", tc.mode, tc.want)
		}
	}
}

// The active navigation item is derived from the page being rendered, so a
// page that forgets to name itself would silently highlight nothing.
func TestNavigationMarksTheCurrentPage(t *testing.T) {
	cfg := testConfig(t, "")
	srv, _, _ := testServer(t, cfg)
	for path, want := range map[string]string{
		"/queue":   `<a href="/queue" class="active">`,
		"/search":  `<a href="/search" class="active">`,
		"/bounces": `<a href="/bounces" class="active">`,
		"/routes":  `<a href="/routes" class="active">`,
		"/config":  `<a href="/config" class="active">`,
	} {
		rec := get(t, srv.Handler(), path)
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: expected %q in the navigation", path, want)
		}
	}
}
