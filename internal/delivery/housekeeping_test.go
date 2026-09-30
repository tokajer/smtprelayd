// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Tokajer

package delivery

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// TestReportQuotaLogsOnlyOnTransition drives reportQuota through a rising
// edge, staying over, a falling edge, and staying under, asserting a log
// line is emitted only on the two transitions -- the entire point of the
// edge-trigger. It also covers the division guard with a zero quota.
func TestReportQuotaLogsOnlyOnTransition(t *testing.T) {
	var buf bytes.Buffer
	h := &Housekeeper{log: slog.New(slog.NewTextHandler(&buf, nil))}

	h.reportQuota(900, 1000, true)
	if out := buf.String(); !strings.Contains(out, "spool is filling up") {
		t.Fatalf("rising edge: want log containing %q, got %q", "spool is filling up", out)
	}
	if out := buf.String(); !strings.Contains(out, "percent=90") {
		t.Fatalf("rising edge: want percent=90, got %q", out)
	}

	buf.Reset()
	h.reportQuota(950, 1000, true)
	if out := buf.String(); out != "" {
		t.Fatalf("still over: want no log, got %q", out)
	}

	buf.Reset()
	h.reportQuota(700, 1000, false)
	if out := buf.String(); !strings.Contains(out, "spool is back below the quota warning threshold") {
		t.Fatalf("falling edge: want log containing %q, got %q", "spool is back below the quota warning threshold", out)
	}

	buf.Reset()
	h.reportQuota(600, 1000, false)
	if out := buf.String(); out != "" {
		t.Fatalf("still under: want no log, got %q", out)
	}

	// Fresh housekeeper so quotaWarned starts false and the rising edge
	// fires, reaching the used*100/quota computation with quota == 0.
	zero := &Housekeeper{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	zero.reportQuota(0, 0, true)
}
