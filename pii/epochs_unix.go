//go:build unix

package pii

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// checkPrivate refuses path unless it is a directory (dir) or a regular
// file, not a symbolic link, owned by the process's user, with no group or
// other permission.
func checkPrivate(path string, dir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) && dir {
			return ErrNoEpoch
		}
		return fmt.Errorf("pii: epoch store: %w", err)
	}
	switch {
	case dir && !fi.IsDir(), !dir && !fi.Mode().IsRegular():
		return fmt.Errorf("pii: epoch store: %s is not a plain %s", path, map[bool]string{true: "directory", false: "file"}[dir])
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("pii: epoch store: %s is open to group or others (%04o): want %04o", path, fi.Mode().Perm(), map[bool]os.FileMode{true: 0o700, false: 0o600}[dir])
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("pii: epoch store: %s is owned by uid %d, not %d", path, st.Uid, os.Geteuid())
	}
	return nil
}

// readNoFollow reads a small key file without following a symbolic link
// or blocking on a FIFO, and checks the file it opened (not only the
// path): regular, private, owned by the process's user.
func readNoFollow(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 || !ok || int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("not a private regular file of uid %d", os.Geteuid())
	}
	return io.ReadAll(io.LimitReader(f, 4096))
}

// lockDir takes an exclusive lock on dir's ".lock" file, without waiting:
// a second process on the same store is refused.
func lockDir(dir string) (io.Closer, error) {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("pii: epoch store lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("pii: epoch store %s is in use by another process: %w", dir, err)
	}
	return f, nil
}
