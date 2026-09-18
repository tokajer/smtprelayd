// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build windows

package config

// dataDirExample names the packaged location in the error that refuses a
// relative service.data_dir. Single quotes, because in a TOML basic string a
// backslash starts an escape and the path would be rejected at load time
// before this message could ever be reached.
const dataDirExample = `for example 'C:\ProgramData\SMTPRelayd'`
