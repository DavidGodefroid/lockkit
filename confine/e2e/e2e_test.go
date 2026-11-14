//go:build e2e && linux

// Package e2e runs the confined agent check end to end (lockkit#133): a
// real console server on a unix socket, and a real lock client (package
// client, testdata/client) run on the host and in containers.
//
//	go test -tags e2e ./confine/...
//
// It needs a container runtime: docker, or the one LOCKKIT_E2E_RUNTIME
// names (podman), with LOCKKIT_E2E_RUN_ARGS added to every run (rootless
// Podman needs --userns=keep-id for the peer to be the test's uid).
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/confine"
	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/kit"
)

var product = kit.Product{Name: "locke2e", Account: "locke2e", ClientsGroup: "locke2e-clients", KeychainService: "locke2e", EnvPrefix: "LOCKE2E_"}

type policy struct {
	Base config.Base `json:"base"`
}

func (p policy) Diff(a config.Policy) []config.Change {
	return config.DiffBase(a.(policy).Base, p.Base)
}
func (p policy) Describe() []string { return []string{"e2e"} }
func (p policy) Profile() console.Profile {
	return console.Profile{Name: "uat", Where: "nowhere", Credentials: console.CredentialsNone, Unconfined: p.Base.Unconfined}
}

type session struct{}

func (session) Close() error { return nil }

type backend struct{ p policy }

func (b backend) Methods() map[string]console.Handler { return nil }
func (b backend) Connect(context.Context, console.Credentials) (console.Session, error) {
	return session{}, nil
}
func (b backend) Checks(context.Context, console.Session) []console.Finding { return nil }
func (b backend) LoadPolicy() (console.Policy, error)                       { return b.p, nil }
func (b backend) Status(console.Session) any                                { return nil }

type lines struct{}

func (lines) Println(string) {}
func (lines) Ask(context.Context, string, time.Duration) (string, bool) {
	return "", false
}
func (lines) AskSecret(context.Context, string) ([]byte, error) { return nil, fmt.Errorf("no secret") }

type outcome struct {
	Served  bool   `json:"served"`
	Code    int    `json:"code"`
	Message string `json:"message"`
	Error   string `json:"error"`
}

func runtimeCmd(t *testing.T) string {
	rt := os.Getenv("LOCKKIT_E2E_RUNTIME")
	if rt == "" {
		rt = "docker"
	}
	if _, err := exec.LookPath(rt); err != nil {
		t.Skipf("no %s: %v", rt, err)
	}
	if out, err := exec.Command(rt, "info").CombinedOutput(); err != nil {
		t.Skipf("%s info: %v\n%s", rt, err, out)
	}
	return rt
}

// serve starts a console server for profile uat in a short temp runtime
// directory and returns that directory.
func serve(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "lke2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(product.RuntimeDirEnv(), dir)
	path, err := ipc.SocketPath(product, "user", "uat")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ipc.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(product, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := console.NewServer(console.ServerConfig{Product: product, Backend: backend{}, Policy: policy{},
		Session: session{}, Audit: log, IO: lines{}, RuntimeGIDs: confine.RuntimeGIDs()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Loop().Serve(ctx, ln, nil)
	}()
	t.Cleanup(func() { cancel(); <-done })
	return dir
}

func buildClient(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "client"), "./testdata/client")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return filepath.Join(dir, "client")
}

func parse(t *testing.T, out []byte) outcome {
	t.Helper()
	var o outcome
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatalf("client output %q: %v", out, err)
	}
	return o
}

func wantRefused(t *testing.T, o outcome, reasons ...string) {
	t.Helper()
	if o.Served || o.Code != ipc.CodeUnconfined {
		t.Fatalf("not refused unconfined: %+v", o)
	}
	for _, r := range reasons {
		if !strings.Contains(o.Message, r+": ") {
			t.Errorf("message %q lacks %s", o.Message, r)
		}
	}
}

func TestConfinedAgentE2E(t *testing.T) {
	rt := runtimeCmd(t)
	bin := buildClient(t)
	dir := serve(t)

	// (a) On the host: refused.
	t.Run("host", func(t *testing.T) {
		if confine.Check(confine.RealEnv()).Confined {
			t.Skip("the test host is itself confined (a lea container)")
		}
		cmd := exec.Command(bin)
		cmd.Env = append(os.Environ(), product.RuntimeDirEnv()+"="+dir)
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		wantRefused(t, parse(t, out), confine.InContainer)
	})

	// The image: the client binary alone.
	ctxDir := t.TempDir()
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctxDir, "client"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctxDir, "Dockerfile"), []byte("FROM scratch\nCOPY client /client\nENTRYPOINT [\"/client\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	image := "lockkit-confine-e2e:" + strconv.Itoa(os.Getpid())
	if out, err := exec.Command(rt, "build", "-q", "-t", image, ctxDir).CombinedOutput(); err != nil {
		t.Fatalf("build image: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command(rt, "rmi", "-f", image).Run() })
	lf := filepath.Join(t.TempDir(), ".lockfamily")
	if err := os.Mkdir(lf, 0o755); err != nil {
		t.Fatal(err)
	}
	// run runs the client in a container with the socket dir and the
	// .lockfamily mounted, read-only unless lfMode is "rw".
	run := func(t *testing.T, lfMode string, extra ...string) outcome {
		t.Helper()
		args := []string{"run", "--rm", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
			"-v", dir + ":" + dir, "-v", lf + ":/work/.lockfamily:" + lfMode, "-w", "/work",
			"-e", product.RuntimeDirEnv() + "=" + dir}
		args = append(args, strings.Fields(os.Getenv("LOCKKIT_E2E_RUN_ARGS"))...)
		args = append(args, extra...)
		args = append(args, image)
		out, err := exec.Command(rt, args...).Output()
		if err != nil {
			t.Fatalf("%s %v: %v", rt, args, err)
		}
		return parse(t, out)
	}

	// (b) In a container with only the socket dir and a read-only
	// .lockfamily: served.
	t.Run("container", func(t *testing.T) {
		if o := run(t, "ro"); !o.Served {
			t.Fatalf("not served: %+v", o)
		}
	})

	// A writable .lockfamily: refused.
	t.Run("container+writable", func(t *testing.T) {
		wantRefused(t, run(t, "rw"), confine.LockfamilyReadOnly)
	})

	// (c) The same container with the host's runtime socket: refused.
	t.Run("container+runtime", func(t *testing.T) {
		const sock = "/var/run/docker.sock"
		fi, err := os.Stat(sock)
		if err != nil || fi.Mode()&os.ModeSocket == 0 {
			t.Skipf("no %s on this host", sock)
		}
		wantRefused(t, run(t, "ro", "-v", sock+":"+sock), confine.NoHostRuntime)
		gid := int(fi.Sys().(*syscall.Stat_t).Gid)
		wantRefused(t, run(t, "ro", "-v", sock+":"+sock, "--group-add", strconv.Itoa(gid)), confine.NoHostRuntime, confine.RuntimeGroup)
	})
}
