//go:build unix

package managed

import (
	"io/fs"
	"syscall"
)

// fileOwner is the uid owning fi.
func fileOwner(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
