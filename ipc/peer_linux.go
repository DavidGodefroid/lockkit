//go:build linux

package ipc

import (
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// PeerAllowed reports whether the process at the other end of c runs as the
// same user as the console (SO_PEERCRED).
func PeerAllowed(c net.Conn) (bool, error) {
	cred, err := PeerCred(c)
	if err != nil {
		return false, err
	}
	return cred.UID == os.Getuid(), nil
}

// PeerCred returns the kernel's record of the process at the other end of
// c (SO_PEERCRED): it cannot be forged by the peer.
func PeerCred(c net.Conn) (Cred, error) {
	uc, err := unixConn(c)
	if err != nil {
		return Cred{}, err
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Cred{}, fmt.Errorf("ipc: peer check: %w", err)
	}
	var cred *unix.Ucred
	var groups []int
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if cerr == nil {
			groups, cerr = peerGroups(int(fd))
		}
	}); err != nil {
		return Cred{}, fmt.Errorf("ipc: peer check: %w", err)
	}
	if cerr != nil {
		return Cred{}, fmt.Errorf("ipc: peer check: %w", cerr)
	}
	return Cred{UID: int(cred.Uid), GID: int(cred.Gid), PID: int(cred.Pid), Groups: groups}, nil
}

// peerGroups reads SO_PEERGROUPS: the peer's supplementary groups as the
// kernel recorded them at connect. The buffer grows when the kernel says
// it is too small (ERANGE, with the length it needs).
func peerGroups(fd int) ([]int, error) {
	n := 64
	for {
		buf := make([]uint32, n)
		size := uint32(len(buf) * 4)
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_PEERGROUPS,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
		if errno == unix.ERANGE && int(size/4) > n && n < 1<<16 {
			n = int(size / 4)
			continue
		}
		if errno != 0 {
			return nil, errno
		}
		out := make([]int, 0, size/4)
		for _, g := range buf[:size/4] {
			out = append(out, int(g))
		}
		return out, nil
	}
}
