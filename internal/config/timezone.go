// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package config

import (
	"fmt"
	"time"
)

// ParseTimezone resolves service.timezone. An empty string returns a nil
// Location, meaning "do not convert": log records keep the process's local
// time and timestamps read back from the store keep the UTC they were
// stored in, exactly as before this option existed. A non-empty value is an
// IANA zone name ("Europe/Vienna"), or the special names "UTC" and "Local"
// that time.LoadLocation already recognises.
func ParseTimezone(s string) (*time.Location, error) {
	if s == "" {
		return nil, nil
	}
	loc, err := time.LoadLocation(s)
	if err != nil {
		return nil, fmt.Errorf("unsupported timezone %q: %w", s, err)
	}
	return loc, nil
}
