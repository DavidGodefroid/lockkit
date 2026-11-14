package confine

import (
	"errors"
	"slices"
	"testing"
)

// fakeEnv is a confined lea container: /.dockerenv, no runtime socket, no
// family state, a read-only .lockfamily in the project.
type fakeEnv struct {
	files     map[string]bool
	sockets   map[string]bool
	readable  map[string]bool
	writable  map[string]bool
	procFiles map[string]string
	env       map[string]string
	goos      string
	cwd, home string
}

func confinedFake() *fakeEnv {
	return &fakeEnv{
		files:     map[string]bool{"/.dockerenv": true, "/work/proj/.lockfamily": true},
		sockets:   map[string]bool{},
		readable:  map[string]bool{"/work/proj/.lockfamily": true},
		writable:  map[string]bool{"/work/proj": true},
		procFiles: map[string]string{},
		env:       map[string]string{},
		goos:      "linux",
		cwd:       "/work/proj/sub",
		home:      "/home/agent",
	}
}

func (f *fakeEnv) Env() Env {
	return Env{
		GOOS:   f.goos,
		Exists: func(p string) bool { return f.files[p] },
		ReadFile: func(p string) ([]byte, error) {
			if s, ok := f.procFiles[p]; ok {
				return []byte(s), nil
			}
			return nil, errors.New("no such file")
		},
		Connects: func(p string) bool { return f.sockets[p] },
		Readable: func(p string) bool { return f.readable[p] },
		Writable: func(p string) bool { return f.writable[p] },
		Getenv:   func(k string) string { return f.env[k] },
		Getwd:    func() (string, error) { return f.cwd, nil },
		HomeDir:  func() (string, error) { return f.home, nil },
	}
}

func TestConfinedWhenAllHold(t *testing.T) {
	r := Check(confinedFake().Env())
	if !r.Confined || len(r.Reasons) != 0 {
		t.Fatalf("Check = %+v, want confined", r)
	}
}

func TestEachReasonAlone(t *testing.T) {
	for _, tc := range []struct {
		want   string
		mutate func(*fakeEnv)
	}{
		{InContainer, func(f *fakeEnv) { delete(f.files, "/.dockerenv") }},
		{InContainer, func(f *fakeEnv) { f.goos = "darwin" }},
		{NoHostRuntime, func(f *fakeEnv) { f.sockets["/var/run/docker.sock"] = true }},
		{NoHostRuntime, func(f *fakeEnv) { f.sockets["/run/podman/podman.sock"] = true }},
		{NoHostRuntime, func(f *fakeEnv) { f.sockets["/run/containerd/containerd.sock"] = true }},
		{NoFamilyState, func(f *fakeEnv) { f.readable["/home/agent/.local/state/lockfamily"] = true }},
		{NoFamilyState, func(f *fakeEnv) {
			f.env["XDG_STATE_HOME"] = "/xdg"
			f.readable["/xdg/lockfamily"] = true
		}},
		{LockfamilyReadOnly, func(f *fakeEnv) { f.writable["/work/proj/.lockfamily"] = true }},
	} {
		f := confinedFake()
		tc.mutate(f)
		r := Check(f.Env())
		if r.Confined || !slices.Equal(r.Reasons, []string{tc.want}) {
			t.Errorf("want only %s, got %+v", tc.want, r)
		}
	}
}

func TestNestedRootlessPodmanAllowed(t *testing.T) {
	f := confinedFake()
	f.sockets["/run/user/1000/podman/podman.sock"] = true
	f.env["DOCKER_HOST"] = "unix:///run/user/1000/podman/podman.sock"
	if r := Check(f.Env()); !r.Confined {
		t.Fatalf("a rootless podman in the container made it unconfined: %+v", r)
	}
}

func TestHostHasEveryReason(t *testing.T) {
	f := confinedFake()
	f.files = map[string]bool{"/work/proj/.lockfamily": true}
	f.sockets["/run/docker.sock"] = true
	f.readable["/home/agent/.local/state/lockfamily"] = true
	f.writable["/work/proj/.lockfamily"] = true
	r := Check(f.Env())
	want := []string{InContainer, NoHostRuntime, NoFamilyState, LockfamilyReadOnly}
	if r.Confined || !slices.Equal(r.Reasons, want) {
		t.Fatalf("Check = %+v, want %v", r, want)
	}
}

func TestNoLockfamilyDirIsFine(t *testing.T) {
	f := confinedFake()
	delete(f.files, "/work/proj/.lockfamily")
	if r := Check(f.Env()); !r.Confined {
		t.Fatalf("no .lockfamily: %+v", r)
	}
}

func TestContainerDetectedFromProc(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"cgroup v1": {"/proc/1/cgroup": "12:pids:/docker/0123abcd\n"},
		"overlay root": {"/proc/self/mountinfo": "22 1 0:21 / / rw,relatime - overlay overlay rw,lowerdir=/l\n" +
			"23 22 0:22 / /proc rw - proc proc rw\n"},
		"docker hostname": {"/proc/self/mountinfo": "30 22 8:1 /var/lib/docker/containers/abc/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n"},
	} {
		f := confinedFake()
		delete(f.files, "/.dockerenv")
		f.procFiles = files
		if r := Check(f.Env()); !r.Confined {
			t.Errorf("%s: %+v", name, r)
		}
	}
	f := confinedFake()
	delete(f.files, "/.dockerenv")
	f.procFiles = map[string]string{
		"/proc/1/cgroup":       "0::/init.scope\n",
		"/proc/self/mountinfo": "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n",
	}
	if r := Check(f.Env()); r.Confined {
		t.Errorf("a host root was taken for a container")
	}
}

func TestReasonTexts(t *testing.T) {
	for _, c := range []string{InContainer, NoHostRuntime, NoFamilyState, LockfamilyReadOnly, RuntimeGroup, OldClient} {
		if !Known(c) || Text(c) == "" {
			t.Errorf("%s has no text", c)
		}
	}
	if Known("whatever") {
		t.Error("unknown code known")
	}
}
