//go:build unix

package console

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/fingerprint"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/sysconf"
)

var testProduct = kit.Product{Name: "lockmq", Account: "lockmq", ClientsGroup: "lockmq-clients",
	KeychainService: "lockmq", EnvPrefix: "LOCKMQ_", Version: "0.1.0"}

func fakeIsolation(sys *sysconf.Config, display string) IsolationEnv {
	return IsolationEnv{
		LoadSys:        func() (*sysconf.Config, error) { return sys, nil },
		Display:        func() sysconf.Display { return sysconf.Display{Kind: display, Detail: display} },
		UID:            func() int { return 900 },
		UserName:       func() (string, error) { return "lockmq", nil },
		LoginUID:       func() (int, bool) { return 900, true },
		TerminalOwner:  func() (int, bool) { return 900, true },
		ClientAllowed:  func(_ *sysconf.Config, uid int) bool { return uid == 1000 },
		ClientGID:      func(*sysconf.Config) (int, error) { return 950, nil },
		AccountExists:  func(uid int) bool { return uid == 0 || uid == 900 || uid == 1000 || uid == 1500 },
		Relay:          func() string { return "" },
		MachinectlUIDs: func() ([]int, bool) { return nil, true },
		DesktopEnv:     func() bool { return false },
		DisplaySet:     func() bool { return false },
		ParentChain: func() ([]sysconf.Proc, error) {
			return []sysconf.Proc{{PID: 2, UID: 900, Comm: "foot"}, {PID: 1, UID: 0, Comm: "systemd"}}, nil
		},
		NewVerifier: func(string) (fingerprint.Verifier, error) { return &fingerprint.Fake{EnrolledN: 1}, nil },
	}
}

func separated() *sysconf.Config {
	return &sysconf.Config{ServiceUser: "lockmq", ClientGroup: "lockmq-clients", SocketDir: "/run/lockmq", X11: sysconf.X11Warn}
}

// A uid removed from the client group loses access at its next connection,
// not at the next console start.
func TestPeerCheckLooksUpMembershipPerConnection(t *testing.T) {
	env := fakeIsolation(separated(), sysconf.DisplayWayland)
	member := true
	lookups := 0
	env.ClientAllowed = func(_ *sysconf.Config, uid int) bool {
		lookups++
		return uid == 1000 && member
	}
	iso, err := CheckIsolation(testProduct, &fakeIO{}, env)
	if err != nil {
		t.Fatal(err)
	}
	lookups = 0
	check := iso.PeerCheck()
	if !check(ipc.Cred{UID: 1000}) {
		t.Fatal("member refused")
	}
	member = false
	if check(ipc.Cred{UID: 1000}) {
		t.Error("a uid removed from the group still connects")
	}
	if lookups != 2 {
		t.Errorf("%d membership lookups for two connections, want 2", lookups)
	}
	if !check(ipc.Cred{UID: 900}) {
		t.Error("the console's own uid refused")
	}
}

// Without a separated setup the console refuses, naming the product's
// commands; a product's test build may allow it.
func TestIsolationSameUserRefused(t *testing.T) {
	io := &fakeIO{}
	_, err := CheckIsolation(testProduct, io, fakeIsolation(nil, sysconf.DisplayX11))
	if err == nil || err.Error() != SameUserRefusal(testProduct) {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"separate account", "through the launcher", "scripts/install.sh", "lockmq doctor"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	// The image refuses the former host install: no text may send there.
	if strings.Contains(err.Error(), " install`") || strings.Contains(testProduct.LauncherHint(), "lockmq install") {
		t.Errorf("refusal names the host install: %v", err)
	}
	if strings.Contains(io.output(), "X11") {
		t.Errorf("X11 warning before the same-user refusal:\n%s", io.output())
	}
	env := fakeIsolation(nil, sysconf.DisplayWayland)
	env.AllowSameUser = true
	if _, err := CheckIsolation(testProduct, io, env); err != nil {
		t.Fatalf("test build refused: %v", err)
	}
}

func TestIsolationX11(t *testing.T) {
	io := &fakeIO{}
	iso, err := CheckIsolation(testProduct, io, fakeIsolation(separated(), sysconf.DisplayX11))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(io.output(), "X11") {
		t.Errorf("no X11 warning:\n%s", io.output())
	}
	if err := iso.RefuseX11IfProduction(true); err == nil {
		t.Error("X11 accepted on a production profile")
	}
	if err := iso.RefuseX11IfProduction(false); err != nil {
		t.Errorf("X11 refused outside production: %v", err)
	}
	sys := separated()
	sys.X11 = sysconf.X11Refuse
	if _, err := CheckIsolation(testProduct, &fakeIO{}, fakeIsolation(sys, sysconf.DisplayX11)); err == nil {
		t.Error("X11 accepted with x11 = refuse")
	}
}

func TestIsolationSeparated(t *testing.T) {
	io := &fakeIO{}
	iso, err := CheckIsolation(testProduct, io, fakeIsolation(separated(), sysconf.DisplayWayland))
	if err != nil {
		t.Fatal(err)
	}
	if iso.Desktop || iso.Verifier != nil || iso.Level() != 0 || iso.Boundary() != "" {
		t.Errorf("session shape marked desktop: %+v", iso)
	}
	if !containsLine(io, "session mode: boundary: kernel") || iso.GID != 950 {
		t.Errorf("out = %q gid %d", io.out, iso.GID)
	}
	check := iso.PeerCheck()
	for uid, want := range map[int]bool{900: true, 1000: true, 1001: false, 0: false} {
		if got := check(ipc.Cred{UID: uid}); got != want {
			t.Errorf("peer uid %d: %v, want %v", uid, got, want)
		}
	}
	cases := map[string]func(*IsolationEnv){
		"wrong account":        func(e *IsolationEnv) { e.UserName = func() (string, error) { return "david", nil } },
		"console in the group": func(e *IsolationEnv) { e.ClientAllowed = func(*sysconf.Config, int) bool { return true } },
		"started through sudo": func(e *IsolationEnv) { e.LoginUID = func() (int, bool) { return 1000, true } },
		"someone else's tty":   func(e *IsolationEnv) { e.TerminalOwner = func() (int, bool) { return 1000, true } },
		"unknown login uid":    func(e *IsolationEnv) { e.LoginUID = func() (int, bool) { return 4242, true } },
		"unknown tty owner":    func(e *IsolationEnv) { e.TerminalOwner = func() (int, bool) { return 4242, true } },
		"no client group":      func(e *IsolationEnv) { e.ClientGID = func(*sysconf.Config) (int, error) { return 0, errors.New("x") } },
	}
	for name, mutate := range cases {
		env := fakeIsolation(separated(), sysconf.DisplayWayland)
		mutate(&env)
		if _, err := CheckIsolation(testProduct, &fakeIO{}, env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	env := fakeIsolation(separated(), sysconf.DisplayWayland)
	env.UserName = func() (string, error) { return "david", nil }
	if _, err := CheckIsolation(testProduct, &fakeIO{}, env); err == nil || !strings.Contains(err.Error(), "/etc/lockmq/system.toml") {
		t.Errorf("wrong account: %v", err)
	}
}

func TestIsolationAcceptsNonClientSession(t *testing.T) {
	env := fakeIsolation(separated(), sysconf.DisplayTTY)
	env.LoginUID = func() (int, bool) { return 1500, true }
	env.TerminalOwner = func() (int, bool) { return 1500, true }
	io := &fakeIO{}
	if _, err := CheckIsolation(testProduct, io, env); err != nil {
		t.Fatal(err)
	}
	if !containsLine(io, "login session of uid 1500, an account outside the client group") {
		t.Errorf("not reported: %q", io.out)
	}
}

func TestIsolationRelays(t *testing.T) {
	for _, tc := range []struct {
		name   string
		relay  string
		uids   []int
		listed bool
		want   string
	}{
		{"desktop session", "", nil, true, ""},
		{"machinectl from the agent's account", sysconf.RelayMachinectl, []int{1000}, true, "uid 1000, which may reach the console"},
		{"machinectl from an administrator", sysconf.RelayMachinectl, []int{1500}, true, ""},
		{"machinectl, caller not found", sysconf.RelayMachinectl, nil, true, "cannot tell which account"},
		{"machinectl from a uid with no account", sysconf.RelayMachinectl, []int{4242}, true, "uid 4242"},
		{"ssh from this machine", sysconf.RelaySSHLoopback, nil, true, "ssh from this machine"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := fakeIsolation(separated(), sysconf.DisplayWayland)
			env.Relay = func() string { return tc.relay }
			env.MachinectlUIDs = func() ([]int, bool) { return tc.uids, tc.listed }
			_, err := CheckIsolation(testProduct, &fakeIO{}, env)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func desktopEnvFake() IsolationEnv {
	env := fakeIsolation(separated(), sysconf.DisplayWayland)
	env.DesktopEnv = func() bool { return true }
	env.LoginUID = func() (int, bool) { return 1000, true } // the agent's desktop session
	env.TerminalOwner = func() (int, bool) { return 900, true }
	return env
}

func TestIsolationDesktopLevels(t *testing.T) {
	io := &fakeIO{}
	iso, err := CheckIsolation(testProduct, io, desktopEnvFake())
	if err != nil {
		t.Fatal(err)
	}
	if !iso.Desktop || iso.Verifier == nil || iso.Level() != 2 || !strings.Contains(iso.Boundary(), "fingerprint") {
		t.Fatalf("iso = %+v", iso)
	}
	env := desktopEnvFake()
	env.NewVerifier = func(string) (fingerprint.Verifier, error) {
		return &fingerprint.Fake{EnrolledErr: fingerprint.ErrNotEnrolled}, nil
	}
	io = &fakeIO{}
	iso, err = CheckIsolation(testProduct, io, env)
	if err != nil || iso.Level() != 1 || iso.Verifier != nil {
		t.Fatalf("level 1: %+v %v", iso, err)
	}
	if !containsLine(io, "no fingerprint enrolled for lockmq: run sudo lockmq enroll") {
		t.Errorf("reason missing: %q", io.out)
	}
}

func TestIsolationDesktopRefusalOrder(t *testing.T) {
	env := desktopEnvFake()
	verifierBuilt := false
	env.NewVerifier = func(string) (fingerprint.Verifier, error) {
		verifierBuilt = true
		return &fingerprint.Fake{EnrolledN: 1}, nil
	}
	env.DisplaySet = func() bool { return true }
	env.TerminalOwner = func() (int, bool) { return 1000, true }
	env.LoginUID = func() (int, bool) { return 1500, true }
	env.ParentChain = func() ([]sysconf.Proc, error) { return nil, nil }
	env.Relay = func() string { return sysconf.RelaySSHLoopback }
	want := []string{"no DISPLAY", "terminal must belong", "outside an allowed desktop session", "no terminal emulator", "ssh from this machine"}
	fix := []func(){
		func() { env.DisplaySet = func() bool { return false } },
		func() { env.TerminalOwner = func() (int, bool) { return 900, true } },
		func() { env.LoginUID = func() (int, bool) { return 1000, true } },
		func() {
			env.ParentChain = func() ([]sysconf.Proc, error) {
				return []sysconf.Proc{{PID: 3, UID: 900, Comm: "gnome-terminal-"}}, nil
			}
		},
		func() { env.Relay = func() string { return "" } },
	}
	for i, w := range want {
		_, err := CheckIsolation(testProduct, &fakeIO{}, env)
		if err == nil || !strings.Contains(err.Error(), w) {
			t.Fatalf("step %d: err = %v, want %q", i, err, w)
		}
		if verifierBuilt {
			t.Fatalf("step %d: fprintd reached before the session checks", i)
		}
		fix[i]()
	}
	if _, err := CheckIsolation(testProduct, &fakeIO{}, env); err != nil {
		t.Fatal(err)
	}
}

type hangingEnrolled struct{ fingerprint.Fake }

func (*hangingEnrolled) Enrolled(ctx context.Context) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestIsolationDesktopEnrolledTimeout(t *testing.T) {
	env := desktopEnvFake()
	env.EnrolledTimeout = 20 * time.Millisecond
	env.NewVerifier = func(string) (fingerprint.Verifier, error) { return &hangingEnrolled{}, nil }
	iso, err := CheckIsolation(testProduct, &fakeIO{}, env)
	if err != nil || iso.Level() != 1 {
		t.Fatalf("iso = %+v, %v", iso, err)
	}
	env.NewVerifier = func(string) (fingerprint.Verifier, error) {
		return nil, fmt.Errorf("%w: fprintd runs as uid 1000, expected 0", fingerprint.ErrWrongOwner)
	}
	if _, err := CheckIsolation(testProduct, &fakeIO{}, env); err == nil || !strings.Contains(err.Error(), "fingerprint reader refused") {
		t.Fatalf("wrong owner: %v", err)
	}
}

// The socket of a separated setup is in the shared directory; otherwise in
// the product's private runtime directory.
func TestIsolationSocketPath(t *testing.T) {
	iso, err := CheckIsolation(testProduct, &fakeIO{}, fakeIsolation(separated(), sysconf.DisplayWayland))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := iso.SocketPath("abcd1234", "uat"); err != nil || p != "/run/lockmq/abcd1234-uat.sock" {
		t.Fatalf("shared: %q %v", p, err)
	}
	t.Setenv("LOCKMQ_RUNTIME_DIR", "/tmp/rt")
	env := fakeIsolation(nil, sysconf.DisplayWayland)
	env.AllowSameUser = true
	iso, _ = CheckIsolation(testProduct, &fakeIO{}, env)
	if p, err := iso.SocketPath("abcd1234", "uat"); err != nil || p != "/tmp/rt/lockmq/abcd1234-uat.sock" || iso.PeerCheck() != nil {
		t.Fatalf("private: %q %v", p, err)
	}
}

func TestPeerContext(t *testing.T) {
	ctx := WithPeer(context.Background(), ipc.Cred{UID: os.Getuid(), PID: os.Getpid()})
	var b audit.Base
	StampPeer(ctx, &b)
	if b.PeerUID == nil || *b.PeerUID != os.Getuid() || b.PeerPID != os.Getpid() {
		t.Fatalf("stamped %+v", b)
	}
	who := PeerText(ctx)
	if !strings.Contains(who, "uid "+strconv.Itoa(os.Getuid())) || !strings.Contains(who, "pid "+strconv.Itoa(os.Getpid())) {
		t.Fatalf("PeerText = %q", who)
	}
	if PeerText(context.Background()) != "" {
		t.Error("no peer, yet a text")
	}
	if _, ok := PeerFrom(WithPeer(context.Background(), ipc.Cred{UID: -1})); ok {
		t.Error("unknown uid counted as a peer")
	}
	if runtime.GOOS == "linux" && ProcessText(1<<30) != "" {
		t.Error("unknown pid named")
	}
}

// A token pasted as service_user matches no account: the refusal names
// the key, never the value.
func TestIsolationNeverEchoesServiceUser(t *testing.T) {
	for _, v := range []string{"glsa_CanarySecretToken123", "https://user:glsa_Canary@h/path?token=glsa_Canary"} {
		sys := separated()
		sys.ServiceUser = v
		io := &fakeIO{}
		_, err := CheckIsolation(testProduct, io, fakeIsolation(sys, sysconf.DisplayWayland))
		if err == nil || strings.Contains(err.Error(), "glsa_Canary") || strings.Contains(io.plain(), "glsa_Canary") || !strings.Contains(err.Error(), "service_user") {
			t.Errorf("%v\n%s", err, io.plain())
		}
	}
}

// A token pasted as client_group is not quoted when allowed_uids lets the
// console account in without the group ever resolving.
func TestIsolationNeverEchoesClientGroup(t *testing.T) {
	sys := separated()
	sys.ClientGroup, sys.AllowedUIDs = "glsa_CanarySecretToken123", []int{900}
	env := fakeIsolation(sys, sysconf.DisplayWayland)
	env.ClientAllowed = func(*sysconf.Config, int) bool { return true }
	_, err := CheckIsolation(testProduct, &fakeIO{}, env)
	if err == nil || strings.Contains(err.Error(), "glsa_Canary") || !strings.Contains(err.Error(), "client_group") {
		t.Errorf("%v", err)
	}
}
