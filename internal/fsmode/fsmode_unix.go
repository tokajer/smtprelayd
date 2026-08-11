// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package fsmode

import (
	"errors"
	"io/fs"
	"os"
)

func restrictFile(path string) error {
	err := os.Chmod(path, 0o600)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
