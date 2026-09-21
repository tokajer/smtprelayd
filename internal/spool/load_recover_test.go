//go:build loadtest

// Load and capacity measurements. Excluded from the ordinary test run by the
// build tag: they create up to a million messages and take minutes, which is
// a measurement, not a regression check. Run them on purpose with
//
//	go test -tags loadtest -run 'TestLoad' -v ./internal/...

package spool

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoadRecoveryAtOneMillion measures only what a restart costs: Open
// reading the queue directory back into the index.
//
// The spool is built by writing the files directly rather than through
// Enqueue, because Enqueue's cost is fsync -- two per message -- and that is
// the enqueue rate, measured separately. Mixing the two would have meant
// spending 83 minutes of fsync to measure a directory walk.
func TestLoadRecoveryAtOneMillion(t *testing.T) {
	for _, n := range []int{100_000, 1_000_000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			dir := t.TempDir()
			queue := filepath.Join(dir, "spool", "queue")
			if err := os.MkdirAll(queue, 0o700); err != nil {
				t.Fatal(err)
			}
			body := make([]byte, 4096)
			for i := range body {
				body[i] = 'x'
			}
			base := time.Now().UTC().Add(-time.Hour)

			start := time.Now()
			for i := 0; i < n; i++ {
				id := loadID(i)
				m := Meta{
					ID: id, Attempts: 0,
					NextAttempt: base, Expires: base.Add(96 * time.Hour),
					Envelope: Envelope{
						From: "device@example.at", To: []string{"someone@partner.example"},
						Client: "printers", Route: "m365", Listener: "smtp",
						RemoteAddr: "10.10.5.42", Helo: "printer-01.example.at",
						Received: base.Add(time.Duration(i) * time.Microsecond),
					},
				}
				b, err := json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(queue, id.String()+".json"), b, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(queue, id.String()+".eml"), body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			built := time.Since(start)

			start = time.Now()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			recover := time.Since(start)

			if s.Len() != n {
				t.Fatalf("recovered %d messages, want %d", s.Len(), n)
			}
			t.Logf("n=%-9d built in %-10v   Open+recover %-10v   (%.0f messages/s recovered)",
				n, built.Round(time.Second), recover.Round(time.Millisecond),
				float64(n)/recover.Seconds())
		})
	}
}

// loadID turns a counter into a queue ID in the alphabet the spool actually
// uses: sixteen characters of [A-Z2-7]. A generated id outside that set is
// refused by ParseID, which recovery calls on every filename -- so a spool
// full of them reads back as empty.
func loadID(i int) ID {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var b [16]byte
	for k := 0; k < 16; k++ {
		b[k] = alphabet[(i>>(5*k))&31]
	}
	return ID(b[:])
}
