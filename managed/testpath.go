//go:build lockfamily_managed_test

package managed

// SetTestPath makes Load read path, without the ownership check, until it
// is called again ("" reads no managed file). It exists only in a build
// with the lockfamily_managed_test tag: a release build has no way to move
// the managed file, so a user cannot point a tool at a looser one.
func SetTestPath(path string) {
	s := newSource(path)
	s.skipOwner = true
	std.mu.Lock()
	defer std.mu.Unlock()
	std.path, std.skipOwner, std.cached = s.path, s.skipOwner, nil
}
