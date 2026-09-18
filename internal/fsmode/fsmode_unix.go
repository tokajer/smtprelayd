// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package fsmode

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func restrictFile(path string) error {
	err := os.Chmod(path, 0o600)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func shareWithGroupOf(path, reference string) (string, error) {
	rfi, err := os.Stat(reference)
	if err != nil {
		return "", err
	}
	rst, ok := rfi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("%s: cannot determine group ownership", reference)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	// -1 leaves the owner alone: only the group is being widened.
	if err := os.Chown(path, -1, int(rst.Gid)); err != nil {
		return "", err
	}
	mode := os.FileMode(0o640)
	if fi.IsDir() {
		mode = 0o750
	}
	if err := os.Chmod(path, mode); err != nil {
		return "", err
	}
	return groupName(rst.Gid), nil
}

// groupName resolves a gid for display only. user.LookupGroupId is pure Go
// (it parses /etc/group), and a gid that does not resolve -- an LDAP group
// this host cannot see, say -- is reported as the number rather than losing
// the answer entirely.
func groupName(gid uint32) string {
	id := strconv.FormatUint(uint64(gid), 10)
	if g, err := user.LookupGroupId(id); err == nil && g.Name != "" {
		return g.Name
	}
	return id
}
