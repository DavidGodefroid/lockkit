//go:build unix

package confine

import "golang.org/x/sys/unix"

// writable is access(2) W_OK: false on a read-only mount (EROFS).
func writable(p string) bool { return unix.Access(p, unix.W_OK) == nil }
