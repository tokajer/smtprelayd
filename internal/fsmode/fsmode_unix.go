// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package fsmode

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

func restrictFile(path string) error {
	err := os.Chmod(path, 0o600)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func shareWithGroupOf(path, reference string) error {
	rfi, err := os.Stat(reference)
	if err != nil {
		return err
	}
	rst, ok := rfi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot determine group ownership", reference)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	// -1 leaves the owner alone: only the group is being widened.
	if err := os.Chown(path, -1, int(rst.Gid)); err != nil {
		return err
	}
	mode := os.FileMode(0o640)
	if fi.IsDir() {
		mode = 0o750
	}
	return os.Chmod(path, mode)
}
