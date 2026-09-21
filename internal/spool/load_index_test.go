//go:build loadtest

// Load and capacity measurements. Excluded from the ordinary test run by the
// build tag: they create up to a million messages and take minutes, which is
// a measurement, not a regression check. Run them on purpose with
//
//	go test -tags loadtest -run 'TestLoad' -v ./internal/...

package spool

import (
	"fmt"
	"runtime"
	"sort"
	"testing"
	"time"
)

// buildIndex fills the in-memory index the dispatcher works against, without
// touching disk: this measures the data structure, not the filesystem.
func buildIndex(n int) (*Spool, time.Time) {
	s := &Spool{index: make(map[ID]*Meta, n), leased: map[ID]bool{}}
	base := time.Now().UTC().Add(-2 * time.Hour)
	for i := 0; i < n; i++ {
		id := loadID(i)
		m := &Meta{
			ID:          id,
			Attempts:    1,
			NextAttempt: base,
			Expires:     base.Add(96 * time.Hour),
		}
		m.Envelope = Envelope{
			From: "device@example.at", To: []string{"someone@partner.example"},
			Origin: "printers", Route: "m365", Listener: "smtp",
			RemoteAddr: "10.10.5.42", Helo: "printer-01.example.at",
			Received: base.Add(time.Duration(i) * time.Microsecond),
		}
		s.putLocked(m)
	}
	return s, time.Now()
}

func heapMB() float64 {
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	return float64(ms.HeapAlloc) / (1 << 20)
}

func TestLoadSpoolIndex(t *testing.T) {
	for _, n := range []int{10_000, 100_000, 1_000_000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			before := heapMB()
			s, now := buildIndex(n)
			after := heapMB()

			// One Claim, which the dispatcher calls once per message.
			const samples = 20
			start := time.Now()
			for i := 0; i < samples; i++ {
				m, ok := s.Claim(now)
				if !ok {
					t.Fatal("nothing due")
				}
				delete(s.leased, m.ID)
			}
			perClaim := time.Since(start) / samples

			start = time.Now()
			depth := s.QueueDepth(now)
			depthTime := time.Since(start)
			queued, deferred := 0, 0
			for _, d := range depth {
				queued += d.Queued
				deferred += d.Deferred
			}

			start = time.Now()
			used, quota, over := s.QuotaWarning()
			quotaTime := time.Since(start)
			_, _, _ = used, quota, over

			t.Logf("n=%-9d heap=%7.1f MB  Claim=%-12v  QueueDepth=%-10v (queued=%d deferred=%d)  QuotaWarning=%v",
				n, after-before, perClaim.Round(time.Microsecond),
				depthTime.Round(time.Microsecond), queued, deferred,
				quotaTime.Round(time.Microsecond))

			// One full drain of the queue, as the dispatcher would do it.
			t.Logf("n=%-9d a full drain at that rate costs %v of Claim alone",
				n, (time.Duration(n) * perClaim).Round(time.Second))
			runtime.KeepAlive(s)
		})
	}
}

func sortByReceived(due []*Meta) {
	sort.Slice(due, func(i, j int) bool {
		return due[i].Envelope.Received.Before(due[j].Envelope.Received)
	})
}

// TestLoadBatchedDrain measures a full drain done in batches. The
// one-at-a-time drain is measured only up to 10 000: at 1 000 000 it is
// 22 hours, which the per-Claim figure above already establishes.
func TestLoadBatchedDrain(t *testing.T) {
	for _, n := range []int{10_000, 100_000, 1_000_000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			s, now := buildIndex(n)
			start := time.Now()
			got, scans := 0, 0
			for {
				ms := s.ClaimBatch(now, 1000, nil)
				if len(ms) == 0 {
					break
				}
				got += len(ms)
				scans++
			}
			elapsed := time.Since(start)
			t.Logf("n=%-9d batched drain %-10v  (%d messages, %d scans)",
				n, elapsed.Round(time.Millisecond), got, scans)
		})
	}
}
