//go:build !unix

package managed

import "io/fs"

// fileOwner cannot tell a trusted owner outside unix: every file is
// refused (DefaultPath reads none there).
func fileOwner(fs.FileInfo) (uint32, bool) { return 0, false }
