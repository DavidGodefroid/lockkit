//go:build !unix

package confine

// RuntimeGIDs is none where sockets have no owning group.
func RuntimeGIDs() []int { return nil }
