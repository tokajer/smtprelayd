// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// LogPath resolves log.file against the data directory. It is the only place
// the two are joined: a path built from a configuration string is exactly
// what CLAUDE.md bans building without validation, and a validation that
// lives somewhere other than the construction is one refactor away from being
// bypassed. Validate calls this and reports the error; main calls it for the
// path it actually opens.
//
// The check is purely lexical. It proves that the configured value cannot
// name a location outside the data directory, not that the resulting path is
// safe to open — a symlink planted inside the data directory would still
// point wherever it points. That is the data directory's own trust check
// (CheckDir, CheckDataDirACL) to enforce, and it is enforced there.
func LogPath(dataDir, file string) (string, error) {
	if file == "" {
		return "", nil // no file logging configured
	}
	if dataDir == "" {
		return "", errors.New("service.data_dir is required to resolve log.file")
	}

	if strings.ContainsRune(file, 0) {
		return "", errors.New("log.file contains a NUL byte")
	}
	if filepath.IsAbs(file) || filepath.VolumeName(file) != "" {
		// filepath.Join would quietly graft an absolute path onto the data
		// directory instead of honouring it, so the value would not mean
		// what whoever wrote it thought it meant. VolumeName also catches
		// the Windows spellings that are not absolute but are not relative
		// to the data directory either: "C:log.txt" and `\\host\share`.
		return "", fmt.Errorf("log.file %q must be relative to service.data_dir", file)
	}

	// Split on both separators regardless of platform: a configuration
	// written on Windows is routinely deployed on Linux, where a backslash
	// is an ordinary character and `..\..\etc` would survive Clean as one
	// long file name rather than being recognised as a traversal.
	for _, elem := range strings.FieldsFunc(file, func(r rune) bool { return r == '/' || r == '\\' }) {
		if elem == ".." {
			return "", fmt.Errorf("log.file %q must not contain a %q path element", file, "..")
		}
	}

	full := filepath.Clean(filepath.Join(dataDir, file))

	// Containment is re-checked on the result rather than trusted to follow
	// from the element scan, so that any spelling the scan does not
	// anticipate still cannot escape.
	base := filepath.Clean(dataDir)
	rel, err := filepath.Rel(base, full)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("log.file %q resolves outside service.data_dir", file)
	}

	return full, nil
}
