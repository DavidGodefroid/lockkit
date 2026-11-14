//go:build !unix

package confine

import "os"

// writable reports a directory whose mode lets its owner write it.
func writable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().Perm()&0o200 != 0
}
