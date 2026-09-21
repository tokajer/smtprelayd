//go:build loadtest && windows

package listener

import "time"

// settleDisk has no syscall.Sync on Windows, so it only waits. That makes the
// Windows figures less comparable across sizes than the Linux ones, which is
// said here rather than left to be discovered in the numbers.
func settleDisk() {
	time.Sleep(5 * time.Second)
}
