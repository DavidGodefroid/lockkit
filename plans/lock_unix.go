//go:build unix

package plans

import (
	"os"
	"syscall"
)

// tryLock takes an exclusive lock on f for its process (flock), without
// waiting: false when another holds it. Closing f releases it.
func tryLock(f *os.File) (bool, error) {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch err {
		case nil:
			return true, nil
		case syscall.EWOULDBLOCK:
			return false, nil
		case syscall.EINTR:
			continue
		}
		return false, err
	}
}
