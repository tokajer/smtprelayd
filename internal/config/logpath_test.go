// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLogPathAcceptsPathsInsideTheDataDir(t *testing.T) {
	dataDir := filepath.Join(string(filepath.Separator), "var", "lib", "smtprelayd")

	for _, file := range []string{"smtprelayd.log", "logs/relay.log", "./smtprelayd.log"} {
		got, err := LogPath(dataDir, file)
		if err != nil {
			t.Fatalf("LogPath(%q) rejected a path inside the data dir: %v", file, err)
		}
		if !strings.HasPrefix(got, dataDir+string(filepath.Separator)) {
			t.Fatalf("LogPath(%q) = %q, which is not under %q", file, got, dataDir)
		}
	}
}

func TestLogPathEmptyFileMeansNoFileLogging(t *testing.T) {
	got, err := LogPath("/var/lib/smtprelayd", "")
	if err != nil || got != "" {
		t.Fatalf("got %q, %v; want an empty path and no error", got, err)
	}
}

// The traversal cases are the point of the function: a privileged daemon must
// not be steerable into writing outside its data directory by a configuration
// value.
func TestLogPathRejectsEscapes(t *testing.T) {
	dataDir := filepath.Join(string(filepath.Separator), "var", "lib", "smtprelayd")

	cases := []struct {
		name string
		file string
	}{
		{"parent traversal", "../../../etc/cron.d/smtprelayd"},
		{"traversal after a legitimate prefix", "logs/../../../etc/passwd"},
		{"bare parent", ".."},
		{"absolute path", filepath.Join(string(filepath.Separator), "etc", "cron.d", "smtprelayd")},
		{"NUL byte", "smtprelayd.log\x00.txt"},
		// A configuration authored on Windows and deployed on Linux: the
		// backslash is an ordinary character there, so Clean would keep this
		// as one long file name instead of recognising the traversal. It is
		// rejected on both platforms rather than only where it happens to be
		// a separator.
		{"windows-style traversal", `..\..\Windows\System32\drivers\etc\hosts`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LogPath(dataDir, tc.file)
			if err == nil {
				t.Fatalf("LogPath(%q) was accepted and resolved to %q, want a rejection", tc.file, got)
			}
			if got != "" {
				t.Fatalf("LogPath returned %q alongside an error; a caller ignoring the error must not get a usable path", got)
			}
		})
	}
}

func TestLogPathRejectsWindowsVolumePaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		// filepath.VolumeName only recognises these on Windows, so the check
		// they exercise is not reachable elsewhere.
		t.Skip("volume names are only parsed on Windows")
	}
	for _, file := range []string{`C:\Windows\Temp\x.log`, `C:x.log`, `\\attacker\share\x.log`} {
		if _, err := LogPath(`C:\ProgramData\SMTPRelayd`, file); err == nil {
			t.Errorf("LogPath(%q) was accepted, want a rejection", file)
		}
	}
}

// Validate must fail the whole configuration, not merely log a warning: an
// unsafe log path is a startup error like every other fail-closed check.
func TestValidateRejectsTraversingLogFile(t *testing.T) {
	c := Defaults()
	c.Service.DataDir = filepath.Join(string(filepath.Separator), "var", "lib", "smtprelayd")
	c.Service.Hostname = "relay.example.at"
	c.Log.File = "../../../etc/cron.d/smtprelayd"

	err := c.Validate()
	if err == nil {
		t.Fatal("Validate accepted a log.file that escapes the data directory")
	}
	if !strings.Contains(err.Error(), "log.file") {
		t.Fatalf("Validate failed for an unrelated reason: %v", err)
	}
}
