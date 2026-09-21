//go:build loadtest && !windows

package listener

import (
	"syscall"
	"time"
)

// settleDisk waits for the pre-fill's own dirty pages to reach disk. Without
// it the measurement races that writeback, and that -- not the size of the
// queue directory -- is what an earlier version of this test was measuring.
func settleDisk() {
	syscall.Sync()
	time.Sleep(3 * time.Second)
}
