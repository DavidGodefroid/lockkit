//go:build unix

package audit

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive lock on f for its process (flock): another
// process appending to the same log waits, so that each record links to
// the line written just before it. Closing f releases it.
func lockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			return err
		}
	}
}
