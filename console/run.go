package console

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/managed"
	"github.com/DavidGodefroid/lockkit/sanitize"
	"github.com/DavidGodefroid/lockkit/secrets"
	"github.com/DavidGodefroid/lockkit/ui"
)

// Options configure Run.
type Options struct {
	// Profile is the profile to serve; ProjectRoot the project whose
	// config holds it ("" for the user config).
	Profile     string
	ProjectRoot string
	IO          IO
	// AllowUnmask and ShowResults are the start-up switches (both refused
	// at level 2; ShowResults refused at level 1 too).
	AllowUnmask, ShowResults bool
	// Auto is refused: auto mode is gone, lockhub decides every request.
	//
	// Deprecated: kept so that products still setting it build; Run
	// refuses it. It goes in the next minor release.
	Auto bool
	// StateDir is the state base (kit.StateBase() when empty).
	StateDir string
	// TTY is the console's terminal device (nil when unknown).
	TTY *os.File
	// Now defaults to time.Now.
	Now func() time.Time
	// Quantum levels response times (Env.Level): 0 is ResponseQuantum, a
	// negative value none.
	Quantum time.Duration
	// Sanitizer scrubs error text; nil is sanitize.New().
	Sanitizer *sanitize.Sanitizer
	// Isolation replaces the system the isolation checks read (tests and
	// a product's test build); nil is RealIsolationEnv.
	Isolation *IsolationEnv
	// Harden replaces Harden (tests).
	Harden func() error
	// VaultRead replaces secrets.VaultReadToken (tests): it reads the login
	// at path with the Vault token typed at the console's start.
	VaultRead func(ctx context.Context, path string, token []byte) (*secrets.VaultCredentials, error)
	// Keychain replaces the product's OS keychain (tests).
	Keychain *secrets.Keychain
	// Ready, when set, is told the socket path once the console listens.
	Ready func(socket string)
	// Hub decides requests on lockhub (HubOptions): required, Run refuses
	// to start without it (ErrNoHub), unless PolicyOnly.
	Hub HubOptions
	// PolicyOnly runs a console that serves its policy and decides no
	// request: the console of a lock whose requests are decided by another
	// process's hub (lockhttp's, whose gate asks lockhub; `lox run` starts
	// such a console without hub flags). It starts without Hub, which must
	// then be empty (ErrPolicyOnlyHub), and without OnHub; every request a
	// handler hands to Env.Approve is refused (ErrPolicyOnly), never asked
	// here. The console's own decisions (its policy at start and at a
	// loosening, :unmask) are still asked on its terminal.
	PolicyOnly bool
	// OnHub, when set, is called with the console's hub once it is open,
	// before any request is served: where a product registers its
	// hubclient.Recompute (hub.Client.SetRecompute). It runs before the
	// policy review, so Run may still fail and close the hub; Run sets the
	// client's OnRequest itself (Hub.Requests), replacing any set here.
	OnHub func(*Hub)

	// loadManaged replaces managed.Load (tests of this package): a release
	// build always reads the machine's managed file.
	loadManaged func(context.Context) (*managed.File, error)
}

// connectTimeout bounds one connection attempt.
const connectTimeout = 30 * time.Second

// starter carries the start-up state of Run.
type starter struct {
	p       kit.Product
	b       Backend
	o       Options
	io      IO
	log     *audit.Log
	profile Profile
	// policy is the policy in force, passed to Backend.Connect.
	policy    Policy
	user      string
	approver  Approver
	lockedOut bool
	keychain  secrets.Keychain
	vaultRead func(ctx context.Context, path string, token []byte) (*secrets.VaultCredentials, error)
	// vaultToken is the Vault token typed at the console's start (nil until
	// asked); memory only, wiped when Run returns.
	vaultToken []byte
	// reviewed is set by startPolicy when the human approved the policy
	// review ("Apply these changes?") of this start.
	reviewed bool
	// nameTyped is set with reviewed when that review was approved by
	// typing the production profile name: the start does not ask it again.
	nameTyped bool
	// managed is the company's managed file in force (nil: none).
	managed *managed.File
}

var errLockedOut = errors.New("console: fingerprint: three non-matching fingers")

func (st *starter) decide(ctx context.Context, d Decision) Result {
	r := st.approver.Approve(ctx, d)
	if r.Outcome == NoFinger {
		st.io.Println(Paint.Fail("denied: " + sanitize.Terminal(r.Err.Error(), false)))
		if errors.Is(r.Err, ErrTooManyNoMatch) {
			st.lockedOut = true
		}
	}
	return r
}

// audit writes b; a failure is told and returned: an approval at start is
// not saved without its record.
func (st *starter) audit(b audit.Base) error {
	b.Profile = st.profile.Name
	b.Managed = managedFP(st.managed)
	var rec audit.Record = b
	if ar, ok := st.b.(interface{ AuditRecord(audit.Base) audit.Record }); ok {
		rec = ar.AuditRecord(b)
	}
	if err := st.log.Append(rec); err != nil {
		st.io.Println("audit log write failed: " + err.Error())
		return err
	}
	return nil
}

// failed records that an approved policy, already on record, was not
// saved, and returns err.
func (st *starter) failed(err error) error {
	_ = st.audit(audit.Base{Event: audit.EventPolicy, Decision: "failed", Error: err.Error()})
	return err
}

// errApprovalUnrecorded: the human approved a policy at start, but the
// record could not be written; nothing is saved and the console stops.
var errApprovalUnrecorded = errors.New("console: the approval of the policy could not be recorded in the audit log")

// Run is a product's `console` command, launched by `lox run` only (the
// hub options are required, ErrNoHub, unless Options.PolicyOnly): the isolation checks, the policy
// review, the production confirmation, the credentials and the connection,
// the backend's checks, the socket, then the request loop until Ctrl-C,
// logout, :quit or a timeout.
func Run(ctx context.Context, p kit.Product, b Backend, o Options) error {
	if o.IO == nil {
		return errors.New("console: no terminal")
	}
	if err := p.Validate(); err != nil {
		return err
	}
	// Hub-attached only, or policy-only without any hub option: refused
	// before any check, prompt or file write.
	if o.PolicyOnly {
		if o.Hub.Enabled() {
			return ErrPolicyOnlyHub
		}
		if o.OnHub != nil {
			return fmt.Errorf("%w: a policy-only console has no hub (Options.OnHub is set)", ErrConfig)
		}
	} else if err := o.Hub.check(); err != nil {
		return err
	}
	if o.Auto {
		return fmt.Errorf("%w: --auto is gone: lockhub decides every request", ErrConfig)
	}
	env := RealIsolationEnv(p, o.TTY)
	if o.Isolation != nil {
		env = *o.Isolation
	}
	// Same-user mode, then any other isolation failure, is refused before
	// any prompt or file write.
	iso, err := CheckIsolation(p, o.IO, env)
	if err != nil {
		return err
	}
	if iso.Verifier != nil {
		defer CloseVerifier(iso.Verifier)
	}
	if iso.Verifier != nil && (o.AllowUnmask || o.ShowResults) {
		return fmt.Errorf("%w: level 2 does not accept --allow-unmask or --show-results", ErrConfig)
	}
	if iso.Level() == 1 && o.ShowResults {
		return fmt.Errorf("%w: level 1 does not accept --show-results: %s", ErrConfig, level1Window)
	}
	harden := Harden
	if o.Harden != nil {
		harden = o.Harden
	}
	hardenErr := harden()
	if hardenErr != nil {
		o.IO.Println(Paint.Warn(red + "could not disable core dumps: " + sanitize.Terminal(hardenErr.Error(), false) + reset))
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.StateDir == "" {
		if o.StateDir, err = kit.StateBase(); err != nil {
			return err
		}
	}
	cur, err := b.LoadPolicy()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if cur.Profile().Name != o.Profile {
		return fmt.Errorf("%w: the backend loaded another profile than --profile names", ErrConfig)
	}
	key := config.ApprovedKey(o.ProjectRoot, o.Profile)
	// The question the console waits for is kept next to its socket, where
	// lox attach and lea read it: they attach after it was printed. On a
	// first start the socket's directory is made here, before the first
	// question; one that cannot be made only keeps the questions on this
	// terminal (Listen refuses it below).
	if socket, err := iso.SocketPath(config.ProjectKeyOf(o.ProjectRoot), o.Profile); err == nil {
		if err := iso.PrepareSocketDir(socket); err != nil {
			o.IO.Println(Paint.Warn(red + "the questions of this start are shown on this terminal only: " + sanitize.Terminal(err.Error(), false) + reset))
		} else {
			RecordQuestions(o.IO, socket)
		}
	}
	// A production profile, loaded or approved before, never runs in an
	// X11 session: refused before the policy review.
	if err := iso.RefuseX11IfProduction(cur.Profile().Production); err != nil {
		return err
	}
	if ap, ok, _ := loadApproved(p, o.StateDir, key, cur); ok {
		if err := iso.RefuseX11IfProduction(ap.Profile().Production); err != nil {
			return err
		}
	}
	log, err := audit.Open(p, o.StateDir)
	if err != nil {
		return err
	}
	// The company's managed file bounds every policy below: unreadable,
	// badly owned or badly signed, it refuses the start (fail closed).
	loadManaged := managed.Load
	if o.loadManaged != nil {
		loadManaged = o.loadManaged
	}
	mf, err := loadManaged(ctx)
	if err != nil {
		_ = log.Append(audit.Base{Event: audit.EventPolicy, Profile: o.Profile, Decision: DecisionRefusedManaged, Error: err.Error()})
		return fmt.Errorf("%w: %v", ErrManaged, err)
	}
	var hub *Hub
	if !o.PolicyOnly {
		if hub, err = OpenHub(p, o.Hub, o.StateDir, o.Now); err != nil {
			return err
		}
		defer hub.Close()
		if o.OnHub != nil {
			o.OnHub(hub)
		}
	}
	appr := NewTypedApprover(o.IO)
	if iso.Desktop {
		appr = NewDesktopTypedApprover(o.IO)
	}
	if iso.Verifier != nil {
		appr = NewFingerprintApprover(o.IO, iso.Verifier, iso.Sys.Finger, FingerDeadline)
	}
	st := &starter{p: p, b: b, o: o, io: o.IO, log: log, profile: cur.Profile(), approver: appr,
		keychain: secrets.NewKeychain(p.KeychainService), vaultRead: secrets.VaultReadToken, managed: mf}
	defer st.wipeVaultToken()
	if o.Keychain != nil {
		st.keychain = *o.Keychain
	}
	if o.VaultRead != nil {
		st.vaultRead = o.VaultRead
	}

	// 1. Policy check.
	approved, refusedFP, err := st.startPolicy(ctx, o.StateDir, key, cur)
	if err != nil {
		return err
	}
	if st.lockedOut {
		st.audit(audit.Base{Event: audit.EventLogin, Decision: "refused", Error: errLockedOut.Error()})
		return errLockedOut
	}
	pr := approved.Profile()
	st.profile, st.policy = pr, approved
	// The start-up refusals of a production profile, applied again by the
	// server when the policy in force becomes production.
	refuseProduction := func() error {
		if hardenErr != nil {
			return fmt.Errorf("console: refused: core dumps could not be disabled (%v) and the profile is production; the secret would be exposed in a dump", hardenErr)
		}
		return iso.RefuseX11IfProduction(true)
	}
	if pr.Production {
		if err := refuseProduction(); err != nil {
			st.audit(audit.Base{Event: audit.EventLogin, Decision: "refused", Error: err.Error()})
			return err
		}
	}

	// 2. Production banner, and the typed profile name when the policy in
	// force was not confirmed by it before.
	where := sanitize.Terminal(pr.Where, false)
	if pr.Production {
		// Context of the questions that follow (PrintContext).
		PrintContext(o.IO, red+strings.Repeat("━", 60)+reset)
		PrintContext(o.IO, red+"  "+ui.MarkWarn+" PRODUCTION profile "+pr.Name+" ("+where+")"+reset)
		PrintContext(o.IO, red+strings.Repeat("━", 60)+reset)
		if st.nameTyped {
			// The review of this start was approved with the name.
			if err := config.SaveApproved(p, o.StateDir, ConfirmedKey(key), approved); err != nil {
				o.IO.Println(Paint.Warn("warning: the confirmation could not be recorded: " + sanitize.Terminal(err.Error(), false)))
			}
		} else if productionNameNeeded(p, o.StateDir, key, approved, st.reviewed) {
			Bell(o.IO)
			ans, ok := o.IO.Ask(ctx, fmt.Sprintf("Type the profile name %q to continue: ", pr.Name), ApprovalTimeout)
			if !ok || strings.TrimSpace(ans) != pr.Name {
				return errors.New("console: production profile not confirmed")
			}
			if err := config.SaveApproved(p, o.StateDir, ConfirmedKey(key), approved); err != nil {
				// Not recorded: the next start asks again.
				o.IO.Println(Paint.Warn("warning: the confirmation could not be recorded: " + sanitize.Terminal(err.Error(), false)))
			}
		} else {
			o.IO.Println(Paint.Dim("profile name typed at an earlier start; the approved policy has not loosened since"))
		}
	}
	o.IO.Println(Paint.OK(fmt.Sprintf("profile %s · %s %s", Paint.Bold(pr.Name), where, Paint.Dim("(approved policy)"))))

	// 3. User, credentials and connection; 4. the backend's checks.
	st.user = pr.User
	if st.user == "" && pr.Credentials != CredentialsNone && pr.Credentials != config.CredentialsVault {
		ans, ok := o.IO.Ask(ctx, "User: ", ApprovalTimeout)
		st.user = strings.TrimSpace(ans)
		if !ok || st.user == "" {
			return errors.New("console: no user")
		}
	}
	sess, err := st.connect(ctx, true)
	if err != nil {
		st.audit(audit.Base{Event: audit.EventLogin, Decision: "failed", Error: err.Error()})
		return err
	}
	if err := st.checks(ctx, sess); err != nil {
		_ = sess.Close()
		st.audit(audit.Base{Event: audit.EventLogin, Decision: "refused", Error: err.Error()})
		return err
	}

	// 5. Socket.
	path, err := iso.SocketPath(config.ProjectKeyOf(o.ProjectRoot), pr.Name)
	if err != nil {
		_ = sess.Close()
		return err
	}
	ln, err := iso.Listen(path)
	if err != nil {
		_ = sess.Close()
		return err
	}
	quantum := o.Quantum
	if quantum == 0 {
		quantum = ResponseQuantum
	}
	// Requests go to the hub (or are refused, policy-only); the console's
	// own decisions (a policy change, unmask) stay with the terminal
	// approver it wraps.
	serverAppr := PolicyOnlyApprover(appr)
	if hub != nil {
		serverAppr = hub.Approver(appr)
	}
	s, err := NewServer(ServerConfig{
		Product: p, Backend: b, Policy: approved, StateDir: o.StateDir, ApprovedKey: key, Session: sess, Audit: log,
		IO: o.IO, Approver: serverAppr, Hub: hub, Level: iso.Level(), Boundary: iso.Boundary(), Now: o.Now,
		AllowUnmask: o.AllowUnmask, ShowResults: o.ShowResults,
		ReconnectPolicy: st.reconnect, Quantum: quantum, PeerAllowed: iso.PeerCheck(), Sanitizer: o.Sanitizer, Refused: refusedFP,
		RefuseProduction: refuseProduction, Managed: mf, LoadManaged: loadManaged,
	})
	if err != nil {
		ln.Close()
		_ = sess.Close()
		st.audit(audit.Base{Event: audit.EventLogin, Decision: "refused", Error: err.Error()})
		return err
	}
	s.record(context.Background(), audit.Base{Event: audit.EventLogin, Decision: "ok"})
	o.IO.Println("")
	o.IO.Println(Paint.Step("Listening on " + sanitize.Terminal(path, false)))
	if o.Ready != nil {
		o.Ready(path)
	}
	if hub != nil {
		hub.Requests(o.IO, func(b audit.Base) { _ = s.record(context.Background(), b) })
		o.IO.Println(Paint.Step("Requests are decided on lockhub at " + sanitize.Terminal(hub.Client.URL(), false) + " as " + hub.Instance))
		wctx, stopWatch := context.WithCancel(ctx)
		watched := make(chan struct{})
		go func() {
			defer close(watched)
			hub.Watch(wctx, o.IO)
		}()
		defer func() { stopWatch(); <-watched }()
	} else {
		o.IO.Println(Paint.Step("Policy only: this console serves its policy and approves no request"))
	}
	var lines <-chan string
	if ls, ok := o.IO.(LineSource); ok {
		lines = ls.Lines()
	}
	serveErr := s.Loop().Serve(ctx, ln, lines)
	s.Close()
	reason, _ := s.Ended()
	s.record(context.Background(), audit.Base{Event: audit.EventLogout, Decision: reason})
	o.IO.Println(Paint.Step("session ended: " + reason))
	return serveErr
}

// ConfirmedKey names, in the approved-policy store, the production policy
// whose profile name the human last typed at start-up under key. Its
// prefix never starts a policy key, which is "user-" or a hex project hash.
func ConfirmedKey(key string) string { return "confirmed-" + key }

// productionNameNeeded reports whether the start of a production profile
// asks for its name: when the human approved a policy review at this start
// (first approval, or a loosening), and when the policy in force loosens
// the one the name was last typed for, or none was (a wrong name leaves
// none). An unreadable record asks.
func productionNameNeeded(p kit.Product, stateDir, key string, inForce Policy, reviewed bool) bool {
	if reviewed {
		return true
	}
	confirmed, ok, err := loadApproved(p, stateDir, ConfirmedKey(key), inForce)
	if err != nil || !ok {
		return true
	}
	return !confirmed.Profile().Production || Loosens(inForce.Diff(confirmed))
}

// loadApproved reads the approved policy of key into a value of cur's type.
func loadApproved(p kit.Product, stateDir, key string, cur Policy) (Policy, bool, error) {
	v := newPolicyLike(cur)
	ok, err := config.LoadApproved(p, stateDir, key, v)
	if err != nil || !ok {
		return nil, false, err
	}
	ap, ok := policyFrom(cur, v)
	if !ok {
		return nil, false, errors.New("console: the approved policy does not decode into the product's policy type")
	}
	return ap, true, nil
}

// startPolicy checks the current policy against the company's managed
// file, then compares it with the approved one (reviewPolicy). A policy
// beyond the managed bounds is refused without any prompt: no human
// approves beyond the company policy. It returns the policy to enforce
// and, when the human refused a loosening, the refused policy's
// fingerprint.
func (st *starter) startPolicy(ctx context.Context, stateDir, key string, cur Policy) (Policy, string, error) {
	if st.managed != nil {
		st.io.Println(Paint.Dim(sanitize.Terminal(st.managed.Describe(), false)))
	}
	if err := st.refuseManaged(cur); err != nil {
		return nil, "", err
	}
	inForce, refusedFP, err := st.reviewPolicy(ctx, stateDir, key, cur)
	if err != nil {
		return nil, "", err
	}
	// The last approved policy, kept when the human refused a loosening,
	// may predate the managed file.
	if err := st.refuseManaged(inForce); err != nil {
		return nil, "", err
	}
	return inForce, refusedFP, nil
}

// refuseManaged refuses p when it goes beyond the managed file's bounds,
// printing and auditing (refused-managed) every violation.
func (st *starter) refuseManaged(p Policy) error {
	err := CheckManaged(st.p, st.b, p, st.managed)
	if err == nil {
		return nil
	}
	lines := ManagedLines(err)
	for _, line := range lines {
		st.io.Println(Paint.Fail(sanitize.Terminal(line, false)))
	}
	st.audit(audit.Base{Event: audit.EventPolicy, Decision: DecisionRefusedManaged, Error: strings.Join(lines, "; ")})
	return err
}

// reviewPolicy compares the current policy with the approved one and asks
// the human to approve a first policy or a loosening.
func (st *starter) reviewPolicy(ctx context.Context, stateDir, key string, cur Policy) (Policy, string, error) {
	io := st.io
	ap, ok, err := loadApproved(st.p, stateDir, key, cur)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v (delete the file to approve the policy again)", ErrConfig, err)
	}
	if !ok {
		// The policy under review is the context of its question.
		PrintContext(io, bold+"First start of profile "+cur.Profile().Name+": review its policy."+reset)
		for _, line := range cur.Describe() {
			PrintContext(io, "  "+sanitize.Terminal(line, false))
		}
		if r := st.decide(ctx, policyDecision(cur.Profile().Production, cur.Profile().Name)); r.Outcome != Approved {
			reason, errText := noFingerFields(r)
			st.audit(audit.Base{Event: audit.EventPolicy, Decision: "refused", Reason: reason, Error: errText})
			return nil, "", errors.New("console: the policy was not approved")
		}
		if st.audit(audit.Base{Event: audit.EventPolicy, Decision: "applied", Approval: st.approver.Mode()}) != nil {
			return nil, "", errApprovalUnrecorded
		}
		if err := config.SaveApprovedManaged(st.p, stateDir, key, cur, managedFP(st.managed)); err != nil {
			return nil, "", st.failed(err)
		}
		st.reviewed, st.nameTyped = true, cur.Profile().Production
		return cur, "", nil
	}
	changes := cur.Diff(ap)
	if len(changes) == 0 {
		return ap, "", nil
	}
	if !Loosens(changes) {
		if err := config.SaveApprovedManaged(st.p, stateDir, key, cur, managedFP(st.managed)); err != nil {
			return nil, "", err
		}
		io.Println("policy tightened since the last session:")
		for _, line := range formatChangesOf(st.b, changes) {
			io.Println(line)
		}
		st.audit(audit.Base{Event: audit.EventPolicy, Decision: "tightened"})
		return cur, "", nil
	}
	PrintContext(io, bold+"The policy of profile "+cur.Profile().Name+" changed since it was approved:"+reset)
	for _, line := range formatChangesOf(st.b, changes) {
		PrintContext(io, line)
	}
	// The name is typed when either side is production: turning
	// production off is a loosening of a production profile.
	production := cur.Profile().Production || ap.Profile().Production
	r := st.decide(ctx, policyDecision(production, cur.Profile().Name))
	if ctx.Err() != nil {
		return nil, "", ctx.Err()
	}
	if r.Outcome != Approved {
		reason, errText := noFingerFields(r)
		st.audit(audit.Base{Event: audit.EventPolicy, Decision: "refused", Reason: reason, Error: errText})
		io.Println("changes refused: the last approved policy applies")
		return ap, config.Fingerprint(cur), nil
	}
	if st.audit(audit.Base{Event: audit.EventPolicy, Decision: "applied", Approval: st.approver.Mode()}) != nil {
		return nil, "", errApprovalUnrecorded
	}
	if err := config.SaveApprovedManaged(st.p, stateDir, key, cur, managedFP(st.managed)); err != nil {
		return nil, "", st.failed(err)
	}
	st.reviewed, st.nameTyped = true, production
	return cur, "", nil
}

// expiringSession is a session whose login expires (a Vault lease).
type expiringSession struct {
	Session
	refreshAt time.Time
}

// CredentialsExpire is when the session must be replaced.
func (s *expiringSession) CredentialsExpire() time.Time { return s.refreshAt }

// Unwrap returns the backend's session (console.Unwrap).
func (s *expiringSession) Unwrap() Session { return s.Session }

// connect obtains the credentials of the profile and opens a session. The
// secret is wiped once Connect returns.
func (st *starter) connect(ctx context.Context, first bool) (Session, error) {
	p := st.profile
	open := func(c Credentials) (Session, error) {
		cctx, cancel := context.WithTimeout(ctx, connectTimeout)
		defer cancel()
		c.Policy = st.policy
		return st.b.Connect(cctx, c)
	}
	switch p.Credentials {
	case CredentialsNone:
		sess, err := open(Credentials{User: st.user})
		if err != nil {
			return nil, fmt.Errorf("console: connect: %s", sanitize.New().Error(err))
		}
		return sess, nil
	case config.CredentialsVault:
		return st.connectVault(ctx, p, open, first)
	}
	return st.connectSecret(ctx, p, open, first)
}

// connectSecret connects with a secret asked of the human or read from the
// OS keychain.
func (st *starter) connectSecret(ctx context.Context, p Profile, open func(Credentials) (Session, error), first bool) (Session, error) {
	ask := func() ([]byte, error) {
		return st.io.AskSecret(ctx, fmt.Sprintf("Password for %s@%s: ", st.user, sanitize.Terminal(p.Host, false)))
	}
	keychain := p.Credentials == config.CredentialsKeychain
	var secret []byte
	var err error
	fromKeychain := false
	if keychain {
		s, legacy, err := st.keychain.Get(p.Name, p.Host, p.Port, p.DefaultPort)
		switch {
		case err == nil:
			secret, fromKeychain = s, true
			if legacy == secrets.LegacyMoved {
				st.io.Println("moved the keychain secret of " + sanitize.Terminal(p.Name+"@"+p.Host, false) + " to its name with the port")
			}
		case errors.Is(err, secrets.ErrNotFound):
			if first {
				st.io.Println("no secret in the OS keychain yet")
			}
		default:
			st.io.Println("OS keychain unavailable, asking instead: " + secrets.Sanitize(err))
			keychain = false
		}
	}
	if secret == nil {
		if secret, err = ask(); err != nil {
			return nil, err
		}
	}
	defer func() { secrets.Wipe(secret) }()
	sess, err := open(Credentials{User: st.user, Secret: secret})
	if err != nil && fromKeychain {
		st.io.Println("connecting with the keychain secret failed: " + secrets.Sanitize(err, secret))
		secrets.Wipe(secret)
		if secret, err = ask(); err != nil {
			return nil, err
		}
		if sess, err = open(Credentials{User: st.user, Secret: secret}); err == nil {
			st.offerSave(ctx, secret, "Replace the secret stored in the OS keychain? [y/N] ")
		}
	} else if err == nil && keychain && !fromKeychain {
		st.offerSave(ctx, secret, "Save in OS keychain? [y/N] ")
	}
	if err != nil {
		return nil, fmt.Errorf("console: connect: %s", secrets.Sanitize(err, secret))
	}
	return sess, nil
}

func (st *starter) offerSave(ctx context.Context, secret []byte, prompt string) {
	if r := st.decide(ctx, Decision{Prompt: prompt, Expected: "y", For: "to save the password in the keychain"}); r.Outcome != Approved {
		return
	}
	if err := st.keychain.Set(st.profile.Name, st.profile.Host, st.profile.Port, secret); err != nil {
		st.io.Println("not saved: " + secrets.Sanitize(err, secret))
		return
	}
	st.io.Println(Paint.OK("saved in the OS keychain"))
}

// vaultTokenTries is how many Vault tokens in a row may be refused before
// a connection gives up.
const vaultTokenTries = 3

// vaultAddr is the Vault server the vault CLI talks to: VAULT_ADDR, or the
// CLI's default.
func vaultAddr() string {
	if a := os.Getenv("VAULT_ADDR"); a != "" {
		return a
	}
	return "https://127.0.0.1:8200"
}

func (st *starter) wipeVaultToken() {
	secrets.Wipe(st.vaultToken)
	st.vaultToken = nil
}

// readVault reads the login at path with the Vault token of the session,
// asked of the human the first time (no echo), and again when Vault refuses
// the read, up to vaultTokenTries times. Vault answers "permission denied"
// alike for an expired or revoked token and for a policy that may not read
// the path, so the warning names both. The token goes to the vault CLI in
// its environment only, never its arguments, a file, a log or the audit
// trail.
func (st *starter) readVault(ctx context.Context, path string) (*secrets.VaultCredentials, error) {
	for try := 1; ; try++ {
		if st.vaultToken == nil {
			tok, err := st.io.AskSecret(ctx, "Vault token for "+sanitize.Terminal(vaultAddr(), false)+": ")
			if err != nil {
				return nil, err
			}
			st.vaultToken = tok
		}
		c, err := st.vaultRead(ctx, path, st.vaultToken)
		if err == nil || !errors.Is(err, secrets.ErrVaultAuth) {
			return c, err
		}
		err = errors.New(secrets.Sanitize(err, st.vaultToken))
		st.wipeVaultToken()
		if try == vaultTokenTries {
			return nil, fmt.Errorf("%w: %v", secrets.ErrVaultAuth, err)
		}
		st.io.Println(Paint.Warn("Vault refused the read: " + err.Error() + ". Enter the token again, or a token whose policy may read " + sanitize.Terminal(path, false)))
	}
}

// connectVault connects with the login read from Vault at every
// connection, never stored. The user comes from the secret, or from the
// profile when the secret has none; a secret naming another user than the
// profile is refused.
func (st *starter) connectVault(ctx context.Context, p Profile, open func(Credentials) (Session, error), first bool) (Session, error) {
	fetched := st.o.Now()
	c, err := st.readVault(ctx, p.VaultPath)
	if err != nil {
		return nil, fmt.Errorf("console: credentials from Vault (%s): %w", sanitize.Terminal(p.VaultPath, false), err)
	}
	defer secrets.Wipe(c.Password)
	user := c.User
	switch {
	case user == "" && p.User == "":
		return nil, fmt.Errorf("console: the Vault secret at %s has no username field: set user in the profile", sanitize.Terminal(p.VaultPath, false))
	case user == "":
		user = p.User
	case p.User != "" && user != p.User:
		return nil, fmt.Errorf("console: the Vault secret at %s is for user %q, the profile sets user %q: remove user from the profile, or fix vault_path",
			sanitize.Terminal(p.VaultPath, false), sanitize.Terminal(user, false), sanitize.Terminal(p.User, false))
	case sanitize.Terminal(user, false) != user:
		return nil, fmt.Errorf("console: the Vault secret at %s has a username with a control or formatting character", sanitize.Terminal(p.VaultPath, false))
	}
	st.user = user
	sess, err := open(Credentials{User: user, Secret: c.Password})
	if err != nil {
		return nil, fmt.Errorf("console: connect with the Vault login of %s: %s", sanitize.Terminal(p.VaultPath, false), secrets.Sanitize(err, c.Password))
	}
	line := "credentials from Vault: " + sanitize.Terminal(p.VaultPath, false) + " · user " + sanitize.Terminal(user, false)
	if c.LeaseID != "" && c.LeaseDuration > 0 {
		// Reconnect with a fresh login before the lease ends, when Vault
		// may revoke the account and its connections.
		line += " · lease " + c.LeaseDuration.String()
		sess = &expiringSession{Session: sess, refreshAt: fetched.Add(c.LeaseDuration - c.LeaseDuration/10)}
	}
	if first {
		st.io.Println(Paint.OK(line))
	} else {
		st.io.Println(line)
	}
	return sess, nil
}

// checks runs the backend's checks of a new session: a refusing finding
// stops; on a production profile any finding stops; otherwise the human
// types "continue".
func (st *starter) checks(ctx context.Context, sess Session) error {
	findings := st.b.Checks(ctx, sess)
	if len(findings) == 0 {
		return nil
	}
	refuse := st.profile.Production
	st.io.Println(Paint.Warn(red + "the checks of the connection found:" + reset))
	for _, f := range findings {
		st.io.Println(red + "  - " + sanitize.Terminal(f.Text, false) + reset)
		refuse = refuse || f.Refuse
	}
	if refuse {
		return fmt.Errorf("console: refused by the checks of the connection: %s", findings[0].Text)
	}
	if r := st.decide(ctx, Decision{Prompt: `Type "continue" to proceed: `, Expected: "continue", Production: true, For: "to continue past the checks"}); r.Outcome != Approved {
		return errors.New("console: stopped at the checks of the connection")
	}
	return nil
}

// reconnect opens a new session under p, the policy in force now, and
// runs the checks again with the start-up rules.
func (st *starter) reconnect(ctx context.Context, p Policy) (Session, error) {
	st.profile, st.policy = p.Profile(), p
	sess, err := st.connect(ctx, false)
	if err != nil {
		return nil, err
	}
	if st.lockedOut {
		_ = sess.Close()
		return nil, ErrTooManyNoMatch
	}
	if err := st.checks(ctx, sess); err != nil {
		_ = sess.Close()
		st.audit(audit.Base{Event: audit.EventLogin, Decision: "refused", Error: "reconnect: " + err.Error()})
		return nil, fmt.Errorf("%w: %v", errReconnectRefused, err)
	}
	return sess, nil
}
