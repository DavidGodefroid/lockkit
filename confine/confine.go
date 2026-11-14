// Package confine is the client's self-check of its containment
// (lockkit#133): whether the agent behind a lock client runs where it
// cannot reach what protects the Locks: the container runtime, the hub
// facades' keys, the project's .lockfamily directory.
//
// The check runs in the agent's environment, where the facts are visible,
// and its Report travels in the hello handshake (ipc.Confinement). The
// console decides; it also checks, on Linux, the kernel's record of the
// peer's groups (RuntimeGIDs), which the client cannot forge.
//
// What it proves: an honest or confused agent run on the host is told so
// and refused by default. What it does not: a host process that lies runs
// as the human and can drive Docker anyway; no lock-side check stops it.
// Confined agents (lea) cannot reach the runtime, the keys or the console's
// terminal, and that is what makes the guarantees hold against prompt
// injection.
package confine

import (
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// The reasons a client is unconfined: each names the check that failed.
// They are fixed codes, sent on the wire; Text gives the human text.
const (
	// InContainer: the client does not run in a container.
	InContainer = "in_container"
	// NoHostRuntime: a rootful container runtime socket connects, or is
	// there behind permissions.
	NoHostRuntime = "no_host_runtime"
	// NoFamilyState: the Lock Family's state directory (the facades'
	// private keys) is readable.
	NoFamilyState = "no_family_state"
	// LockfamilyReadOnly: the project's .lockfamily directory is writable.
	LockfamilyReadOnly = "lockfamily_read_only"
	// RuntimeGroup: the peer holds a group owning a runtime socket
	// (decided by the console from the kernel's record, never reported).
	RuntimeGroup = "runtime_group"
	// OldClient: the client sent no confinement report (decided by the
	// console).
	OldClient = "old_client"
)

var texts = map[string]string{
	InContainer:        "it does not run in a container",
	NoHostRuntime:      "it can reach the host's container runtime",
	NoFamilyState:      "it can read the Lock Family's keys",
	LockfamilyReadOnly: "it can write the project's .lockfamily directory",
	RuntimeGroup:       "it holds a group that owns a container runtime socket",
	OldClient:          "its client is too old to report its confinement",
}

// Known reports whether code is one of the reasons above.
func Known(code string) bool {
	_, ok := texts[code]
	return ok
}

// Text is the human text of a reason code; "" for an unknown one.
func Text(code string) string { return texts[code] }

// Report is the outcome of Check.
type Report struct {
	Confined bool
	// Reasons are the codes of the checks that failed, in check order.
	Reasons []string
}

// RuntimeSockets are the rootful container runtime sockets. A rootless
// runtime socket inside the container (lea's nested Podman under
// /run/user/<uid>/) is not one: it runs in the container's namespaces.
var RuntimeSockets = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/run/podman/podman.sock",
	"/run/containerd/containerd.sock",
}

// Env is what Check reads; tests replace its functions.
type Env struct {
	// GOOS is runtime.GOOS: only Linux has containers.
	GOOS string
	// Exists reports whether a path exists.
	Exists func(path string) bool
	// ReadFile reads a file (/proc/1/cgroup, /proc/self/mountinfo).
	ReadFile func(path string) ([]byte, error)
	// Connects reports whether a unix socket at path accepts a connection,
	// or refuses it for want of permission: a runtime socket mounted into
	// the container counts even when this account may not use it.
	Connects func(path string) bool
	// Readable reports whether the directory at path can be listed.
	Readable func(path string) bool
	// Writable reports whether the directory at path is writable
	// (access(2) W_OK: a read-only mount is not).
	Writable func(path string) bool
	Getenv   func(string) string
	Getwd    func() (string, error)
	HomeDir  func() (string, error)
}

// RealEnv is the process's own environment.
func RealEnv() Env {
	return Env{
		GOOS: runtime.GOOS,
		Exists: func(p string) bool {
			_, err := os.Lstat(p)
			return err == nil
		},
		ReadFile: os.ReadFile,
		Connects: func(p string) bool {
			c, err := net.DialTimeout("unix", p, time.Second)
			if err != nil {
				return errors.Is(err, fs.ErrPermission)
			}
			c.Close()
			return true
		},
		Readable: func(p string) bool {
			f, err := os.Open(p)
			if err != nil {
				return false
			}
			defer f.Close()
			_, err = f.Readdirnames(1)
			return err == nil || errors.Is(err, io.EOF)
		},
		Writable: writable,
		Getenv:   os.Getenv,
		Getwd:    os.Getwd,
		HomeDir:  os.UserHomeDir,
	}
}

// Check runs the four checks of env. The client is confined when all
// hold: it runs in a container, no rootful runtime socket connects, the
// Lock Family's state directory is absent or unreadable, and the nearest
// .lockfamily directory above the working directory, if any, is not
// writable.
func Check(env Env) Report {
	var reasons []string
	if !inContainer(env) {
		reasons = append(reasons, InContainer)
	}
	for _, s := range RuntimeSockets {
		if env.Connects(s) {
			reasons = append(reasons, NoHostRuntime)
			break
		}
	}
	if dir := stateDir(env); dir != "" && env.Readable(dir) {
		reasons = append(reasons, NoFamilyState)
	}
	if dir := nearestLockfamily(env); dir != "" && env.Writable(dir) {
		reasons = append(reasons, LockfamilyReadOnly)
	}
	return Report{Confined: len(reasons) == 0, Reasons: reasons}
}

// inContainer: the runtimes' marker files, or a container in
// /proc/1/cgroup (cgroup v1) or a container root in /proc/self/mountinfo.
// Never on another system than Linux.
func inContainer(env Env) bool {
	if env.GOOS != "linux" {
		return false
	}
	if env.Exists("/.dockerenv") || env.Exists("/run/.containerenv") {
		return true
	}
	if b, err := env.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		for _, m := range []string{"/docker/", "/docker-", "/kubepods", "/libpod-", "/containerd/", "/lxc/"} {
			if strings.Contains(s, m) {
				return true
			}
		}
	}
	if b, err := env.ReadFile("/proc/self/mountinfo"); err == nil {
		return containerRoot(string(b))
	}
	return false
}

// containerRoot reports a mountinfo whose root mount is an overlay (the
// image layers of a container) or that holds a runtime's per-container
// files (/etc/hostname bound from /var/lib/docker/containers/...).
func containerRoot(mountinfo string) bool {
	for _, line := range strings.Split(mountinfo, "\n") {
		if strings.Contains(line, "/docker/containers/") || strings.Contains(line, "/containers/storage/overlay-containers/") {
			return true
		}
		// <id> <parent> <maj:min> <root> <mount point> <options> ... - <fstype> <source> <super options>
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		f := strings.Fields(pre)
		if len(f) < 5 || f[4] != "/" {
			continue
		}
		if t := strings.Fields(post); len(t) > 0 && (t[0] == "overlay" || t[0] == "fuse-overlayfs") {
			return true
		}
	}
	return false
}

// stateDir is $XDG_STATE_HOME/lockfamily, ~/.local/state/lockfamily by
// default; "" when neither is known.
func stateDir(env Env) string {
	if x := env.Getenv("XDG_STATE_HOME"); x != "" && filepath.IsAbs(x) {
		return filepath.Join(x, "lockfamily")
	}
	home, err := env.HomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".local", "state", "lockfamily")
}

// nearestLockfamily is the first .lockfamily directory at or above the
// working directory, "" when there is none.
func nearestLockfamily(env Env) string {
	dir, err := env.Getwd()
	if err != nil {
		return ""
	}
	dir = filepath.Clean(dir)
	for {
		p := filepath.Join(dir, ".lockfamily")
		if env.Exists(p) {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
