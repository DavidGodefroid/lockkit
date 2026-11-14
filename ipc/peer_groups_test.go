//go:build linux || darwin

package ipc

import (
	"net"
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// TestPeerCredGroups: PeerCred reports the peer's supplementary groups,
// here the process's own (a socketpair connects it to itself).
func TestPeerCredGroups(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fds[0]), "a")
	defer f.Close()
	unix.Close(fds[1])
	c, err := net.FileConn(f)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cred, err := PeerCred(c)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range want {
		if !slices.Contains(cred.Groups, g) {
			t.Errorf("group %d missing from %v", g, cred.Groups)
		}
	}
	if cred.UID != os.Getuid() || !cred.HasGroup([]int{os.Getgid()}) {
		t.Errorf("cred %+v", cred)
	}
	if cred.HasGroup([]int{-5}) {
		t.Error("HasGroup of a gid it does not hold")
	}
}
