// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

//go:build !windows

package config

// dataDirExample names the packaged location in the error that refuses a
// relative service.data_dir, so the message carries the answer and not only
// the complaint.
const dataDirExample = `for example /var/lib/smtprelayd`
