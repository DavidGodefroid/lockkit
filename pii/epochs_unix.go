//go:build unix

package pii

import (
	"fmt"
	"io"
	"os"
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

// readNoFollow reads a small file without following a symbolic link.
func readNoFollow(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 4096))
}
