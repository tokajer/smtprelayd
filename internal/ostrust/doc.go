// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package ostrust holds the filesystem-ownership checks, the Windows
// data-directory ACL, and the DPAPI secret binding that the configuration
// loader and the CLI rely on to refuse a configuration, a secret file or a
// data directory that an unprivileged local user could tamper with.
package ostrust
