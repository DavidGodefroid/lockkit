//go:build unix

package confine

import (
	"os"
	"slices"
	"syscall"
)

// RuntimeGIDs are the groups that own a rootful runtime socket of this
// machine (RuntimeSockets) and may write it: a peer holding one can drive
// the runtime, whatever it reports. A socket its group cannot write (rootful
// Podman's root:root 0600) gives none. A console run on the host computes
// them itself; a containerized one is told them (--runtime-gids).
func RuntimeGIDs() []int {
	var out []int
	for _, s := range RuntimeSockets {
		fi, err := os.Stat(s)
		if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm()&0o020 == 0 {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && !slices.Contains(out, int(st.Gid)) {
			out = append(out, int(st.Gid))
		}
	}
	return out
}
