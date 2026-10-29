//go:build windows

package audit

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive lock on f for its process (LockFileEx):
// another process appending to the same log waits, so that each record
// links to the line written just before it. Closing f releases it.
func lockFile(f *os.File) error {
	var ol windows.Overlapped
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, ^uint32(0), ^uint32(0), &ol)
}
