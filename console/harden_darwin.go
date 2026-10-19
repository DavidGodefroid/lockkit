package console

import "golang.org/x/sys/unix"

// Harden disables core dumps (RLIMIT_CORE=0).
func Harden() error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
}
