//go:build !unix && !windows

package plans

import "os"

// tryLock is a no-op where the system has no file lock.
func tryLock(*os.File) (bool, error) { return true, nil }
