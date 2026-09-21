//go:build loadtest

// Load and capacity measurements. Excluded from the ordinary test run by the
// build tag: they create up to a million messages and take minutes, which is
// a measurement, not a regression check. Run them on purpose with
//
//	go test -tags loadtest -run 'TestLoad' -v ./internal/...

package listener

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tokajer/smtprelayd/internal/config"
	"github.com/tokajer/smtprelayd/internal/spool"
	"github.com/tokajer/smtprelayd/internal/store"
)

// concServer binds a listener with no client dialogue attached, so the test
// can open as many of its own as it likes.
func concServer(t *testing.T, cfg *config.Config) (addr string, sp *spool.Spool) {
	t.Helper()
	dir := t.TempDir()
	sp, err := spool.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir, discardLog(), 90, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

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
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("Run did not return after cancellation")
		}
	})
	return set.servers[0].ln.Addr().String(), sp
}

type concResult struct {
	queued, refused, failed atomic.Int64
	firstErr                atomic.Value
}

// oneMessage runs a full SMTP transaction. It returns "queued", "refused"
// (the server said 421 -- a cap, which is a correct answer, not a failure)
// or an error.
func oneMessage(addr, body string) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		return "", err
	}
	br := bufio.NewReader(c)

	read := func() (string, error) {
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return "", err
			}
			line = strings.TrimRight(line, "\r\n")
			if len(line) < 4 || line[3] != '-' {
				return line, nil
			}
		}
	}
	say := func(s string) error {
		_, err := fmt.Fprintf(c, "%s\r\n", s)
		return err
	}

	banner, err := read()
	if err != nil {
		return "", fmt.Errorf("banner: %w", err)
	}
	if strings.HasPrefix(banner, "421") {
		return "refused", nil
	}
	if !strings.HasPrefix(banner, "220") {
		return "", fmt.Errorf("banner was %q", banner)
	}

	for _, step := range []struct{ cmd, want string }{
		{"EHLO probe.test", "250"},
		{"MAIL FROM:<device@example.test>", "250"},
		{"RCPT TO:<ops@example.test>", "250"},
		{"DATA", "354"},
	} {
		if err := say(step.cmd); err != nil {
			return "", fmt.Errorf("%s: %w", step.cmd, err)
		}
		got, err := read()
		if err != nil {
			return "", fmt.Errorf("%s: %w", step.cmd, err)
		}
		if strings.HasPrefix(got, "421") {
			return "refused", nil
		}
		if !strings.HasPrefix(got, step.want) {
			return "", fmt.Errorf("%s: got %q, want %s", step.cmd, got, step.want)
		}
	}
	if err := say("Subject: load\r\n\r\n" + body + "\r\n."); err != nil {
		return "", fmt.Errorf("body: %w", err)
	}
	got, err := read()
	if err != nil {
		return "", fmt.Errorf("after dot: %w", err)
	}
	if strings.HasPrefix(got, "421") {
		return "refused", nil
	}
	if !strings.HasPrefix(got, "250") {
		return "", fmt.Errorf("after dot: got %q", got)
	}
	_ = say("QUIT")
	return "queued", nil
}

// TestLoadConcurrentSessions opens many SMTP sessions at once and checks that
// every one of them ends in an answer: a queued message, or a 421 that names
// the cap. Nothing may hang, crash, or be silently dropped, and the spool has
// to hold exactly as many messages as were acknowledged -- an acknowledged
// message that is not in the spool is mail the relay lost.
func TestLoadConcurrentSessions(t *testing.T) {
	sizes := []struct{ clients, cap int }{{5000, 5000}, {10000, 10000}}
	if n := envInt("LOAD_SESSIONS", 0); n > 0 {
		sizes = []struct{ clients, cap int }{{n / 2, n / 2}, {n, n}}
	}
	for _, tc := range sizes {
		t.Run(fmt.Sprintf("clients=%d_cap=%d", tc.clients, tc.cap), func(t *testing.T) {
			cfg := queueConfig()
			cfg.Limits.MaxConnections = tc.cap
			cfg.Clients[0].MaxConnections = 0 // no per-client cap; the global one is under test
			addr, sp := concServer(t, cfg)

			// Wrapped well under the 1000-octet line limit the server
			// enforces: an unwrapped body is refused, correctly, and would
			// measure the refusal rather than the load.
			body := strings.TrimRight(strings.Repeat(strings.Repeat("x", 76)+"\r\n", 27), "\r\n")
			var res concResult
			var wg sync.WaitGroup
			start := make(chan struct{})
			begin := time.Now()
			for i := 0; i < tc.clients; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					switch outcome, err := oneMessage(addr, body); {
					case err != nil:
						res.failed.Add(1)
						res.firstErr.CompareAndSwap(nil, err.Error())
					case outcome == "queued":
						res.queued.Add(1)
					default:
						res.refused.Add(1)
					}
				}()
			}
			close(start)
			wg.Wait()
			elapsed := time.Since(begin)

			var ms runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&ms)

			q, r, f := res.queued.Load(), res.refused.Load(), res.failed.Load()
			t.Logf("clients=%-5d cap=%-5d  queued=%-5d refused(421)=%-5d failed=%-3d  %v  goroutines=%d heap=%.0f MB",
				tc.clients, tc.cap, q, r, f, elapsed.Round(time.Millisecond),
				runtime.NumGoroutine(), float64(ms.HeapAlloc)/(1<<20))

			if f > 0 {
				t.Errorf("%d session(s) ended without an SMTP answer; first: %v", f, res.firstErr.Load())
			}
			if q+r != int64(tc.clients) {
				t.Errorf("%d sessions accounted for, want %d", q+r, tc.clients)
			}
			// Every acknowledged message must be on disk. Fewer is lost mail.
			if got := int64(sp.Len()); got != q {
				t.Errorf("spool holds %d messages but %d were acknowledged", got, q)
			}
		})
	}
}

// TestLoadSustainedThroughput is the shape that actually matters: a bounded
// number of sessions open at once, carrying message after message, for as
// long as the relay runs. Millions of simultaneous sockets are not reachable
// on one host -- see the arithmetic in the report -- but millions of messages
// through a few hundred sessions are what a relay does for a living.
func TestLoadSustainedThroughput(t *testing.T) {
	// Scaled down on a small machine -- the Windows VM has four cores and
	// roughly 4 GB -- without changing what is measured.
	workers := envInt("LOAD_WORKERS", 400)
	perWork := envInt("LOAD_PER_WORKER", 250)
	expected := int64(workers * perWork)
	cfg := queueConfig()
	cfg.Limits.MaxConnections = workers + 50
	cfg.Clients[0].MaxConnections = 0
	addr, sp := concServer(t, cfg)

	body := strings.TrimRight(strings.Repeat(strings.Repeat("x", 76)+"\r\n", 27), "\r\n")
	var queued, failed atomic.Int64
	var firstErr atomic.Value
	var peakGoroutines atomic.Int64

	var wg sync.WaitGroup
	begin := time.Now()
	stop := make(chan struct{})
	go func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if g := int64(runtime.NumGoroutine()); g > peakGoroutines.Load() {
					peakGoroutines.Store(g)
				}
			}
		}
	}()

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWork; i++ {
				switch outcome, err := oneMessage(addr, body); {
				case err != nil:
					failed.Add(1)
					firstErr.CompareAndSwap(nil, err.Error())
				case outcome == "queued":
					queued.Add(1)
				default:
					failed.Add(1)
					firstErr.CompareAndSwap(nil, "unexpected 421 below the cap")
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	elapsed := time.Since(begin)

	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)

	q, f := queued.Load(), failed.Load()
	t.Logf("%d workers x %d messages: queued=%d failed=%d in %v = %.0f msg/s, peak goroutines=%d, heap=%.0f MB, spool=%d",
		workers, perWork, q, f, elapsed.Round(time.Millisecond),
		float64(q)/elapsed.Seconds(), peakGoroutines.Load(),
		float64(ms.HeapAlloc)/(1<<20), sp.Len())
	if f > 0 {
		t.Errorf("%d message(s) failed; first: %v", f, firstErr.Load())
	}
	if q != expected {
		t.Errorf("queued %d, want %d", q, expected)
	}
	if int64(sp.Len()) != q {
		t.Errorf("spool holds %d but %d were acknowledged", sp.Len(), q)
	}
	t.Logf("at this rate one million messages take %v",
		(time.Duration(float64(1_000_000) / float64(q) * float64(elapsed))).Round(time.Second))
}

// envInt reads an integer from the environment, so the same harness runs at
// the size the machine under it can hold.
func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
