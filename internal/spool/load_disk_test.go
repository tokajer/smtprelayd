//go:build loadtest

// Load and capacity measurements. Excluded from the ordinary test run by the
// build tag: they create up to a million messages and take minutes, which is
// a measurement, not a regression check. Run them on purpose with
//
//	go test -tags loadtest -run 'TestLoad' -v ./internal/...

package spool

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dirMB reports how much the spool occupies on disk.
func dirMB(dir string) float64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			total += fi.Size()
		}
		return nil
	})
	return float64(total) / (1 << 20)
}

// TestLoadSpoolOnDisk measures the two things a restart depends on: how fast
// messages land in the spool, and how long Open takes to rebuild the index
// from them afterwards. The second is the startup path -- a service that
// takes minutes there looks hung to systemd and is killed by the Windows SCM.
func TestLoadSpoolOnDisk(t *testing.T) {
	body := strings.Repeat("x", 4096)
	for _, n := range []int{100_000, 1_000_000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			env := Envelope{
				From: "device@example.at", To: []string{"someone@partner.example"},
				Client: "printers", Route: "m365", Listener: "smtp",
				RemoteAddr: "10.10.5.42", Received: time.Now().UTC(),
			}
			start := time.Now()
			for i := 0; i < n; i++ {
				if _, err := s.Enqueue(env, strings.NewReader(body), 0, 96*time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			enqueue := time.Since(start)

			start = time.Now()
			s2, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			reopen := time.Since(start)

			if s2.Len() != n {
				t.Errorf("reopened spool holds %d messages, want %d", s2.Len(), n)
			}
			t.Logf("n=%-7d Enqueue %-10v (%.0f msg/s)   Open+recover %-10v   on disk %.0f MB",
				n, enqueue.Round(time.Millisecond), float64(n)/enqueue.Seconds(),
				reopen.Round(time.Millisecond), dirMB(dir))
		})
	}
}
