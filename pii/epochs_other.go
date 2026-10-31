//go:build !unix

package pii

import (
	"fmt"
	"io"
	"os"
)

// checkPrivate refuses path unless it is a directory (dir) or a regular
// file and not a symbolic link. Permissions are the platform's (ACLs).
func checkPrivate(path string, dir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) && dir {
			return ErrNoEpoch
		}
		return fmt.Errorf("pii: epoch store: %w", err)
	}
	if dir && !fi.IsDir() || !dir && !fi.Mode().IsRegular() {
		return fmt.Errorf("pii: epoch store: %s is not a plain file or directory", path)
	}
	return nil
}

func readNoFollow(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 4096))
}
