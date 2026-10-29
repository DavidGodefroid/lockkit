//go:build !unix && !windows

package audit

import "os"

// lockFile is a no-op where the system has no file lock: one process
// writes the log (the in-process lock still holds).
func lockFile(*os.File) error { return nil }
