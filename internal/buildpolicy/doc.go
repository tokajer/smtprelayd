// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

// Package buildpolicy holds no code. It exists to carry the test that enforces
// the constructs CLAUDE.md and docs/SECURITY.md ban outright, so that the ban
// is a build failure rather than a review convention.
//
// The test covers this module's own source. The full dependency graph, where a
// transitive import could reintroduce a banned package on one GOOS only, is
// checked separately in CI with `go list -deps` per target platform.
package buildpolicy
