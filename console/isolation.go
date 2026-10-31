package console

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/fingerprint"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/sysconf"
)

// ErrConfig marks usage and configuration errors (exit code 3).
var ErrConfig = errors.New("configuration error")

// Isolation is how the console is kept apart from the agent: in a
// separated setup (sysconf) the console runs as the service account and
// serves the client group over a shared socket, either in its own login
// session (the session shape: the kernel keeps the agent out of its
// terminal) or in a terminal of the console account opened on the agent's
// desktop (the desktop shape: every approval also takes a fingerprint).
// Without one it refuses to start (except when IsolationEnv.AllowSameUser
// is set by a product's test build).
type Isolation struct {
	Product kit.Product
	Sys     *sysconf.Config
	Display sysconf.Display
	Self    int
	GID     int
	// Desktop is the desktop shape; Verifier is then its fingerprint
	// reader (nil at level 1 and in the session shape).
	Desktop  bool
	Verifier fingerprint.Verifier

	allowed func(uid int) bool
}

// IsolationEnv holds what CheckIsolation reads from the system; tests
// replace its functions (RealIsolationEnv is the real one).
type IsolationEnv struct {
	LoadSys       func() (*sysconf.Config, error)
	Display       func() sysconf.Display
	UID           func() int
	UserName      func() (string, error)
	LoginUID      func() (int, bool)
	TerminalOwner func() (int, bool)
	ClientAllowed func(sys *sysconf.Config, uid int) bool
	ClientGID     func(sys *sysconf.Config) (int, error)
	// AccountExists reports whether uid names an account.
	AccountExists func(uid int) bool
	// Relay reports a session opened through a relay (sysconf.SessionRelay).
	Relay func() string
	// MachinectlUIDs lists the callers of running `machinectl shell`
	// processes (sysconf.MachinectlShellUIDs).
	MachinectlUIDs func() ([]int, bool)
	// DesktopEnv reports <PREFIX>DESKTOP=1: the desktop shape is asked for.
	DesktopEnv func() bool
	// DisplaySet reports a non-empty DISPLAY.
	DisplaySet func() bool
	// ParentChain lists the ancestors of the process, from the parent up
	// (sysconf.ParentChain).
	ParentChain func() ([]sysconf.Proc, error)
	// NewVerifier opens the fingerprint reader of user.
	NewVerifier func(user string) (fingerprint.Verifier, error)
	// EnrolledTimeout bounds the start-up question to fprintd; past it, the
	// reader counts as unavailable. 0 is 10s.
	EnrolledTimeout time.Duration
	// AllowSameUser lets the console run without a separated setup, in the
	// agent's account. Only a product's test build sets it (a build tag):
	// no config file, flag, environment variable or client may.
	AllowSameUser bool
}

// RealIsolationEnv is the environment of a console of p on terminal tty
// (nil when unknown).
func RealIsolationEnv(p kit.Product, tty *os.File) IsolationEnv {
	return IsolationEnv{
		LoadSys: func() (*sysconf.Config, error) { return sysconf.Load(p) },
		Display: sysconf.DetectDisplay,
		UID:     os.Getuid,
		UserName: func() (string, error) {
			u, err := user.Current()
			if err != nil {
				return "", err
			}
			return u.Username, nil
		},
		LoginUID: sysconf.LoginUID,
		TerminalOwner: func() (int, bool) {
			if tty == nil {
				return 0, false
			}
			return sysconf.TerminalOwner(tty)
		},
		ClientAllowed: func(sys *sysconf.Config, uid int) bool { return sys.ClientAllowed(uid) },
		ClientGID:     func(sys *sysconf.Config) (int, error) { return sys.ClientGID() },
		AccountExists: func(uid int) bool {
			_, err := user.LookupId(strconv.Itoa(uid))
			return err == nil
		},
		Relay:          sysconf.SessionRelay,
		MachinectlUIDs: sysconf.MachinectlShellUIDs,
		DesktopEnv:     func() bool { return os.Getenv(p.Env("DESKTOP")) == "1" },
		DisplaySet:     func() bool { return os.Getenv("DISPLAY") != "" },
		ParentChain:    sysconf.ParentChain,
		NewVerifier: func(user string) (fingerprint.Verifier, error) {
			return fingerprint.NewFprintd(fingerprint.Options{User: user, OwnerUID: 0})
		},
	}
}

// SameUserRefusal is the one text of the same-user refusal of p.
func SameUserRefusal(p kit.Product) string {
	return "console: refused: the console must run in a separate account, apart from the agent's, or the agent could read its terminal and type into it; " +
		p.LauncherHint() + "; `" + p.Name + " doctor` checks the setup"
}

// SameUserRefused is the refusal of a console of p without a separated
// setup (sys nil, as sysconf.Load returns it), or nil.
func SameUserRefused(p kit.Product, sys *sysconf.Config, allowSameUser bool) error {
	if sys == nil && !allowSameUser {
		return errors.New(SameUserRefusal(p))
	}
	return nil
}

// CheckIsolation applies the separation rules before any prompt and before
// the console writes any state. Warnings go to the terminal; a violation is
// an error. The production rule on X11 needs the profile and is applied
// later, by RefuseX11IfProduction.
func CheckIsolation(p kit.Product, io IO, env IsolationEnv) (*Isolation, error) {
	sys, err := env.LoadSys()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if err := SameUserRefused(p, sys, env.AllowSameUser); err != nil {
		return nil, err
	}
	iso := &Isolation{Product: p, Sys: sys, Display: env.Display(), Self: env.UID(), GID: -1}

	if iso.Display.Kind == sysconf.DisplayX11 {
		msg := "the console runs in an X11 session (" + iso.Display.Detail + "): any X client, the agent's included, can read its keyboard and screen and send it keystrokes"
		if sys != nil && sys.X11 == sysconf.X11Refuse {
			return nil, errors.New("console: refused: " + msg + "; run it in a Wayland session or on a text console")
		}
		io.Println(red + "warning: " + msg + "; prefer a Wayland session" + reset)
	}

	if sys == nil { // only a test build gets here (AllowSameUser)
		io.Println(red + "same-user mode: test build only" + reset)
		return iso, nil
	}

	name, err := env.UserName()
	if err != nil {
		return nil, fmt.Errorf("console: cannot read the current account: %w", err)
	}
	if name != sys.ServiceUser {
		// service_user is not quoted: it matched no account here, and it
		// may be a value pasted in the wrong key.
		return nil, fmt.Errorf("console: this machine separates the console from the agent (%s): run the console as the account its service_user names, in its own login session, not as %q",
			sysconf.File(p), name)
	}
	if env.ClientAllowed(sys, iso.Self) {
		return nil, fmt.Errorf("console: the account %q may also connect as a client (group %q or allowed_uids): the separation would be void", name, sys.ClientGroup)
	}
	if env.DesktopEnv() {
		return iso.desktopShape(io, env, name)
	}
	// Another account's session or terminal is refused when that account
	// may reach the console (the agent's: it could read the terminal and
	// type into it) or names no account. An account outside the client
	// group (an administrator handing the console off with sudo, su or
	// machinectl, while the agents run under an account of their own) is
	// out of the agent's reach.
	agentSide := func(uid int) bool { return !env.AccountExists(uid) || env.ClientAllowed(sys, uid) }
	if lu, ok := env.LoginUID(); ok && lu >= 0 && lu != iso.Self {
		if agentSide(lu) {
			return nil, fmt.Errorf("console: started from the login session of uid %d (sudo or su), which may reach the console: that account shares this terminal and display; log in as %q in a session of its own",
				lu, sys.ServiceUser)
		}
		io.Println(fmt.Sprintf("started from the login session of uid %d, an account outside the client group", lu))
	}
	if owner, ok := env.TerminalOwner(); ok && owner != iso.Self && agentSide(owner) {
		return nil, fmt.Errorf("console: the terminal belongs to uid %d, which may reach the console: its owner can read it and type into it; open a terminal in %q's own session",
			owner, sys.ServiceUser)
	}
	if err := checkRelay(io, env, sys, agentSide); err != nil {
		return nil, err
	}
	gid, err := env.ClientGID(sys)
	if err != nil {
		return nil, fmt.Errorf("%w: %v (%s)", ErrConfig, err, p.LauncherHint())
	}
	iso.GID = gid
	iso.allowed = func(uid int) bool { return env.ClientAllowed(sys, uid) }
	io.Println("session mode: boundary: kernel")
	return iso, nil
}

// RefuseX11IfProduction applies the production rule once the profile is
// known: a production profile never runs in an X11 session.
func (iso *Isolation) RefuseX11IfProduction(production bool) error {
	if production && iso.Display.Kind == sysconf.DisplayX11 {
		return errors.New("console: refused: production profile in an X11 session; run it in a Wayland session or on a text console")
	}
	return nil
}

// desktopShape accepts a console of the service account opened in a
// terminal on the agent's desktop session (<PREFIX>DESKTOP=1): Wayland with
// no DISPLAY (no X client reads its keyboard), a terminal and a terminal
// emulator of the console account (the agent's account can neither read
// nor write them), started from an allowed client's login session, no
// relay. The checks run in this order; the first failure is the refusal. It
// never falls back to the session shape. With a fingerprint reader and a
// finger enrolled for the console account it is level 2 (every approval
// also takes a finger); without one it is level 1 (typed approvals, the
// boundary line in red); a reader that errs otherwise refuses.
func (iso *Isolation) desktopShape(io IO, env IsolationEnv, name string) (*Isolation, error) {
	sys := iso.Sys
	if iso.Display.Kind != sysconf.DisplayWayland || env.DisplaySet() {
		detail := iso.Display.Detail
		if detail == "" {
			detail = iso.Display.Kind
		}
		return nil, errors.New("console: desktop mode needs a Wayland socket and no DISPLAY (" + detail + ")")
	}
	if owner, ok := env.TerminalOwner(); !ok || owner != iso.Self {
		return nil, fmt.Errorf("console: desktop mode: the terminal must belong to %q", name)
	}
	if lu, ok := env.LoginUID(); !ok || !env.ClientAllowed(sys, lu) {
		return nil, errors.New("console: desktop mode: started outside an allowed desktop session")
	}
	chain, err := env.ParentChain()
	if err != nil {
		return nil, fmt.Errorf("console: desktop mode: cannot read the parent processes: %v", err)
	}
	if !hasEmulator(chain, iso.Self) {
		return nil, fmt.Errorf("console: desktop mode: no terminal emulator of %q above this process", name)
	}
	agentSide := func(uid int) bool { return !env.AccountExists(uid) || env.ClientAllowed(sys, uid) }
	if err := checkRelay(io, env, sys, agentSide); err != nil {
		return nil, err
	}
	gid, err := env.ClientGID(sys)
	if err != nil {
		return nil, fmt.Errorf("%w: %v (%s)", ErrConfig, err, iso.Product.LauncherHint())
	}
	iso.GID, iso.Desktop = gid, true
	iso.allowed = func(uid int) bool { return env.ClientAllowed(sys, uid) }
	v, why, err := openReader(iso.Product, env, sys.ServiceUser)
	if err != nil {
		return nil, err
	}
	if v == nil {
		iso.Verifier = nil
		io.Println(red + "desktop mode, level 1: boundary: your desktop — the agent can read this window and type into it" + reset)
		io.Println(red + "no fingerprint: " + why + reset)
		return iso, nil
	}
	iso.Verifier = v
	io.Println("desktop mode, level 2: approvals by fingerprint (fprintd), boundary: your desktop session")
	return iso, nil
}

// openReader opens the fingerprint reader of the console account. A reader
// that is absent, not answering or without an enrolled finger gives a nil
// verifier and the reason (level 1); any other error, a fprintd of the
// wrong account included, is a refusal. A verifier it does not return is
// closed.
func openReader(p kit.Product, env IsolationEnv, account string) (fingerprint.Verifier, string, error) {
	refusal := func(err error) error {
		return fmt.Errorf("console: desktop mode: fingerprint reader refused: %v", err)
	}
	v, err := env.NewVerifier(account)
	if err != nil {
		if errors.Is(err, fingerprint.ErrUnavailable) && !errors.Is(err, fingerprint.ErrWrongOwner) {
			return nil, "no reader", nil
		}
		return nil, "", refusal(err)
	}
	timeout := env.EnrolledTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ectx, cancel := context.WithTimeout(context.Background(), timeout)
	n, err := v.Enrolled(ectx)
	cancel()
	if err == nil && n <= 0 {
		err = fingerprint.ErrNotEnrolled
	}
	if err == nil {
		return v, "", nil
	}
	CloseVerifier(v)
	switch {
	case errors.Is(err, fingerprint.ErrNotEnrolled):
		return nil, "no fingerprint enrolled for " + account + ": run sudo " + p.Name + " enroll", nil
	case errors.Is(err, fingerprint.ErrUnavailable), errors.Is(err, fingerprint.ErrTimeout),
		errors.Is(err, context.DeadlineExceeded):
		if errors.Is(err, fingerprint.ErrWrongOwner) {
			return nil, "", refusal(err)
		}
		return nil, "no reader", nil
	}
	return nil, "", refusal(err)
}

// Level is the security level of the isolation: 2 for the desktop shape
// with a fingerprint reader, 1 for the desktop shape without, 0 for the
// session shape (the kernel is the boundary).
func (iso *Isolation) Level() int {
	switch {
	case !iso.Desktop:
		return 0
	case iso.Verifier != nil:
		return 2
	}
	return 1
}

// Boundary names where the approval screen stands, for the status screen.
func (iso *Isolation) Boundary() string {
	switch iso.Level() {
	case 2:
		return "your desktop session; approvals take a fingerprint"
	case 1:
		return "your desktop: the agent can read this window and type into it"
	}
	return ""
}

// CloseVerifier releases a verifier that holds a connection (fprintd's).
func CloseVerifier(v fingerprint.Verifier) {
	if c, ok := v.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

// hasEmulator reports whether chain holds one of the desktop terminal
// emulators running as uid.
func hasEmulator(chain []sysconf.Proc, uid int) bool {
	for _, p := range chain {
		if p.UID != uid {
			continue
		}
		for _, e := range sysconf.DesktopEmulators {
			// The kernel truncates comm to 15 bytes (TASK_COMM_LEN - 1).
			if p.Comm == e || len(e) > sysconf.CommLen && p.Comm == e[:sysconf.CommLen] {
				return true
			}
		}
	}
	return false
}

// checkRelay refuses a session of the console account that relays the
// terminal of an account on the agent's side. loginuid and the terminal
// owner name the console account there, so CheckIsolation alone accepts
// it. A machinectl shell is accepted only when every running `machinectl
// shell` belongs to an account out of the agent's reach; an SSH login from
// this machine is refused, since its client cannot be identified.
func checkRelay(io IO, env IsolationEnv, sys *sysconf.Config, agentSide func(uid int) bool) error {
	switch env.Relay() {
	case sysconf.RelayMachinectl:
		uids, ok := env.MachinectlUIDs()
		if !ok || len(uids) == 0 {
			return fmt.Errorf("console: refused: this session is a machinectl shell and the console cannot tell which account opened it; log in as %q in a session of its own", sys.ServiceUser)
		}
		for _, uid := range uids {
			if agentSide(uid) {
				return fmt.Errorf("console: refused: this machinectl shell may relay the terminal of uid %d, which may reach the console: that account could read it and type into it; log in as %q in a session of its own",
					uid, sys.ServiceUser)
			}
		}
		io.Println("started from a machinectl shell of an account outside the client group")
	case sysconf.RelaySSHLoopback:
		return fmt.Errorf("console: refused: this session is an ssh from this machine, which relays the terminal of an account the console cannot identify; log in as %q in a session of its own (or ssh from another machine)", sys.ServiceUser)
	}
	return nil
}

// SocketPath is the console socket of a project and profile: in the
// shared socket directory of a separated setup, else in the user's runtime
// directory.
func (iso *Isolation) SocketPath(projectKey, profile string) (string, error) {
	if iso.Sys != nil {
		return ipc.SharedSocketPath(iso.Sys.SocketDir, projectKey, profile)
	}
	return ipc.SocketPath(iso.Product, projectKey, profile)
}

// Listen opens the socket.
func (iso *Isolation) Listen(path string) (net.Listener, error) {
	if iso.Sys != nil {
		return ipc.ListenShared(iso.Product, path, iso.GID)
	}
	return ipc.Listen(path)
}

// PeerCheck decides which peers are served: the console's own account and,
// in a separated setup, allowed_uids and the client group. The group is
// looked up at every connection: a uid removed from it loses access at its
// next connection, not at the next console start. Nil means the console's
// own uid only.
func (iso *Isolation) PeerCheck() func(ipc.Cred) bool {
	if iso.Sys == nil {
		return nil // the default: the console's own uid
	}
	return func(c ipc.Cred) bool {
		return c.UID == iso.Self || iso.allowed(c.UID)
	}
}

// peerKey carries the requesting client's credentials in a request context.
type peerKey struct{}

// WithPeer returns ctx carrying the credentials of the client behind a
// request.
func WithPeer(ctx context.Context, c ipc.Cred) context.Context {
	return context.WithValue(ctx, peerKey{}, c)
}

// PeerFrom returns the client behind the request of ctx.
func PeerFrom(ctx context.Context) (ipc.Cred, bool) {
	c, ok := ctx.Value(peerKey{}).(ipc.Cred)
	return c, ok && c.UID >= 0
}

// StampPeer sets the peer fields of b from the client behind ctx: its uid,
// pid and account name. The process name, chosen by the agent, stays on
// the screen (PeerText) and out of the audit log.
func StampPeer(ctx context.Context, b *audit.Base) {
	c, ok := PeerFrom(ctx)
	if !ok {
		return
	}
	uid := c.UID
	b.PeerUID = &uid
	if c.PID > 0 {
		b.PeerPID = c.PID
	}
	if u, err := user.LookupId(strconv.Itoa(c.UID)); err == nil {
		b.PeerUser = u.Username
	}
}

// PeerText describes the client behind a request for the approval screen.
func PeerText(ctx context.Context) string {
	c, ok := PeerFrom(ctx)
	if !ok {
		return ""
	}
	who := "uid " + strconv.Itoa(c.UID)
	if u, err := user.LookupId(strconv.Itoa(c.UID)); err == nil {
		who += " (" + u.Username + ")"
	}
	if c.PID > 0 {
		who += " · pid " + strconv.Itoa(c.PID)
		if p := ProcessText(c.PID); p != "" {
			who += " · " + p
		}
	}
	return who
}

// ProcessText names the process behind pid on Linux: its executable path
// when the kernel lets the console read it (a process of its own account),
// else the name the process gave itself, labelled as such; "" elsewhere.
// The uid and pid are the kernel's; the name is the process's choice.
func ProcessText(pid int) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	dir := "/proc/" + strconv.Itoa(pid)
	if exe, err := os.Readlink(dir + "/exe"); err == nil && exe != "" {
		return "exe " + exe
	}
	if b, err := os.ReadFile(dir + "/comm"); err == nil {
		if name := strings.TrimSpace(string(b)); name != "" {
			return "process " + strconv.Quote(name) + " (self-reported name)"
		}
	}
	return ""
}
