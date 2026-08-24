// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package canary sends a periodic synthetic test message through a
// configured route, so an operator notices a working delivery path even
// without real traffic. A failure is reported through the existing bounce
// digest mechanism rather than a separate alerting path.
package canary
