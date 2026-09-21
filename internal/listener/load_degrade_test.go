//go:build loadtest

package listener

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// prefill writes n message pairs straight into the queue directory, without
// going through Enqueue: the point is to have the directory already hold that
// many files, not to measure putting them there.
func prefill(t *testing.T, dir string, n int) {
	t.Helper()
	queue := filepath.Join(dir, "spool", "queue")
	if err := os.MkdirAll(queue, 0o700); err != nil {
		t.Fatal(err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	body := make([]byte, 4096)
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < n; i++ {
		var b [16]byte
		for k := 0; k < 16; k++ {
			b[k] = alphabet[(i>>(5*k))&31]
		}
		id := string(b[:])
		m := map[string]any{
			"id": id, "attempts": 0,
			"next_attempt": base.Format(time.RFC3339Nano),
			"expires":      base.Add(96 * time.Hour).Format(time.RFC3339Nano),
			"envelope": map[string]any{
				"from": "device@example.at", "to": []string{"someone@partner.example"},
				"client": "printers", "route": "r", "listener": "smtp",
				"remote_addr": "10.10.5.42", "received": base.Format(time.RFC3339Nano),
			},
		}
		j, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(queue, id+".json"), j, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(queue, id+".eml"), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestLoadThroughputVersusSpoolSize answers why the same test measured 199
// messages a second over 16 000 messages and 56 over 100 000: every message
// is two files in one flat directory, so both creating a file and fsyncing
// the directory get more expensive as it fills.
func TestLoadThroughputVersusSpoolSize(t *testing.T) {
	const measure = 4000
	for _, existing := range []int{0, 50_000, 200_000} {
		t.Run(fmt.Sprintf("existing=%d", existing), func(t *testing.T) {
			dir := t.TempDir()
			if existing > 0 {
				prefill(t, dir, existing)
				// Without this the measurement races the kernel flushing the
				// pre-fill's own dirty pages, and that -- not the directory
				// size -- is what the first version of this test was
				// measuring: 50 000 came out five times slower than 200 000,
				// repeatably, because only the smaller set was still under
				// the dirty-page threshold and therefore still draining when
				// the load started.
				settleDisk()
			}
			sp, err := spool.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			st, err := store.Open(dir, discardLog(), 90, true)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			if sp.Len() != existing {
				t.Fatalf("spool recovered %d, expected the %d pre-filled", sp.Len(), existing)
			}

			cfg := queueConfig()
			cfg.Limits.MaxConnections = 450
			cfg.Clients[0].MaxConnections = 0
			cfg.Listeners[0].Address = "127.0.0.1:0"
			set, err := New(cfg, sp, discardLog(), st, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := set.Bind(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { set.Run(ctx); close(done) }()
			t.Cleanup(func() {
				cancel()
				<-done
			})
			addr := set.servers[0].ln.Addr().String()

			body := strings.TrimRight(strings.Repeat(strings.Repeat("x", 76)+"\r\n", 27), "\r\n")
			var ok, bad atomic.Int64
			var wg sync.WaitGroup
			const workers = 400
			per := measure / workers
			start := time.Now()
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < per; i++ {
						if outcome, err := oneMessage(addr, body); err != nil || outcome != "queued" {
							bad.Add(1)
						} else {
							ok.Add(1)
						}
					}
				}()
			}
			wg.Wait()
			elapsed := time.Since(start)
			t.Logf("spool already holds %-7d files=%-7d -> %d messages in %v = %.0f msg/s (failed %d)",
				existing, existing*2, ok.Load(), elapsed.Round(time.Millisecond),
				float64(ok.Load())/elapsed.Seconds(), bad.Load())
		})
	}
}
