//go:build windows

package audit

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive lock on f for its process (LockFileEx):
// another process appending to the same log waits, so that each record
// links to the line written just before it. Closing f releases it.
//
// Windows byte-range locks are mandatory: a lock over the file's data
// would make a concurrent reader (a stats command) fail. The lock is
// taken on one byte far past any audit log's end, which every writer
// locks and no reader touches.
func lockFile(f *os.File) error {
	ol := windows.Overlapped{Offset: lockOffset, OffsetHigh: lockOffsetHigh}
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol)
}

// The locked byte is at 2^62, past any log.
const (
	lockOffset     = 0
	lockOffsetHigh = 1 << 30
)
