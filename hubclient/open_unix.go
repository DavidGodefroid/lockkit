//go:build unix

package hubclient

import "syscall"

// nonBlock opens without waiting for a writer (a FIFO).
const nonBlock = syscall.O_NONBLOCK
