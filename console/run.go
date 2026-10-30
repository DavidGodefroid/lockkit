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
	// Auto, AllowUnmask and ShowResults are the start-up switches (all
	// three refused at level 2; ShowResults refused at level 1 too).
	Auto, AllowUnmask, ShowResults bool
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
	// VaultRead replaces secrets.VaultRead (tests).
	VaultRead func(ctx context.Context, path string) (*secrets.VaultCredentials, error)
	// Keychain replaces the product's OS keychain (tests).
	Keychain *secrets.Keychain
	// Ready, when set, is told the socket path once the console listens.
	Ready func(socket string)
	// Hub, when enabled, decides requests on lockhub (HubOptions); --auto
	// is refused with it.
	Hub HubOptions
	// OnHub, when set, is called with the console's hub once it is open,
	// before any request is served: where a product registers its
	// hubclient.Recompute (hub.Client.SetRecompute).
	OnHub func(*Hub)
}

// connectTimeout bounds one connection attempt.
const connectTimeout = 30 * time.Second

// starter carries the start-up state of Run.
type starter struct {
	p         kit.Product
	b         Backend
	o         Options
	io        IO
	log       *audit.Log
	profile   Profile
	user      string
	approver  Approver
	lockedOut bool
	keychain  secrets.Keychain
	vaultRead func(ctx context.Context, path string) (*secrets.VaultCredentials, error)
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

// Run is a product's `console` command: the isolation checks, the policy
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
	if iso.Verifier != nil && (o.Auto || o.AllowUnmask || o.ShowResults) {
		return fmt.Errorf("%w: level 2 does not accept --auto, --allow-unmask or --show-results", ErrConfig)
	}
	if o.Hub.Enabled() {
		if err := o.Hub.check(); err != nil {
			return err
		}
		if o.Auto {
			return fmt.Errorf("%w: --auto does not go with --hub: the hub decides", ErrConfig)
		}
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
		return fmt.Errorf("%w: the backend loaded profile %q, not %q", ErrConfig, cur.Profile().Name, o.Profile)
	}
	key := config.ApprovedKey(o.ProjectRoot, o.Profile)
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
	var hub *Hub
	if o.Hub.Enabled() {
		if hub, err = OpenHub(p, o.Hub, o.StateDir, o.Now); err != nil {
			return err
		}
		defer hub.Close()
		if o.OnHub != nil {
			o.OnHub(hub)
		}
	} else {
		// Rollback of hub mode: the plans it left pending are withdrawn,
		// and a run of their tickets is refused (Server.Handle).
		ws, err := WithdrawStandalone(p, o.StateDir)
		for _, w := range ws {
			o.IO.Println(Paint.Warn(fmt.Sprintf("hub mode is off: %d pending ticket(s) of %s withdrawn; the hub hears of it at the next start with --hub --instance %s",
				len(w.Tickets), sanitize.Terminal(w.Instance, false), sanitize.Terminal(w.Instance, false))))
		}
		if err != nil {
			o.IO.Println(Paint.Warn("hub mode is off, and its pending plans could not all be withdrawn (they stay pending and could run after a restart with --hub; deny them in lockhub): " + sanitize.Terminal(err.Error(), false)))
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
		keychain: secrets.NewKeychain(p.KeychainService), vaultRead: secrets.VaultRead}
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
	st.profile = pr
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

	// 2. Production banner and typed profile name.
	where := sanitize.Terminal(pr.Where, false)
	if pr.Production {
		o.IO.Println(red + strings.Repeat("━", 60) + reset)
		o.IO.Println(red + "  " + ui.MarkWarn + " PRODUCTION profile " + pr.Name + " (" + where + ")" + reset)
		o.IO.Println(red + strings.Repeat("━", 60) + reset)
		Bell(o.IO)
		ans, ok := o.IO.Ask(ctx, fmt.Sprintf("Type the profile name %q to continue: ", pr.Name), ApprovalTimeout)
		if !ok || strings.TrimSpace(ans) != pr.Name {
			return errors.New("console: production profile not confirmed")
		}
		if o.Auto {
			o.IO.Println("--auto is ignored on production profiles: every request is prompted")
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
	var serverAppr Approver = appr
	if hub != nil {
		serverAppr = hub.Approver(appr)
	}
	s, err := NewServer(ServerConfig{
		Product: p, Backend: b, Policy: approved, StateDir: o.StateDir, ApprovedKey: key, Session: sess, Audit: log,
		IO: o.IO, Approver: serverAppr, Hub: hub, Level: iso.Level(), Boundary: iso.Boundary(), Now: o.Now,
		Auto: o.Auto, AllowUnmask: o.AllowUnmask, ShowResults: o.ShowResults,
		Reconnect: st.reconnect, Quantum: quantum, PeerAllowed: iso.PeerCheck(), Sanitizer: o.Sanitizer, Refused: refusedFP,
		RefuseProduction: refuseProduction,
	})
	if err != nil {
		ln.Close()
		_ = sess.Close()
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
		o.IO.Println(Paint.Step("Requests are decided on lockhub at " + sanitize.Terminal(o.Hub.URL, false) + " as " + hub.Instance))
		wctx, stopWatch := context.WithCancel(ctx)
		watched := make(chan struct{})
		go func() {
			defer close(watched)
			hub.Watch(wctx, o.IO)
		}()
		defer func() { stopWatch(); <-watched }()
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

// startPolicy compares the current policy with the approved one. It
// returns the policy to enforce and, when the human refused a loosening,
// the refused policy's fingerprint.
func (st *starter) startPolicy(ctx context.Context, stateDir, key string, cur Policy) (Policy, string, error) {
	io := st.io
	ap, ok, err := loadApproved(st.p, stateDir, key, cur)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v (delete the file to approve the policy again)", ErrConfig, err)
	}
	if !ok {
		io.Println(bold + "First start of profile " + cur.Profile().Name + ": review its policy." + reset)
		for _, line := range cur.Describe() {
			io.Println("  " + sanitize.Terminal(line, false))
		}
		if r := st.decide(ctx, Decision{Prompt: "Apply these changes? [y/N] ", Expected: "y", For: "to apply the policy changes"}); r.Outcome != Approved {
			reason, errText := noFingerFields(r)
			st.audit(audit.Base{Event: audit.EventPolicy, Decision: "refused", Reason: reason, Error: errText})
			return nil, "", errors.New("console: the policy was not approved")
		}
		if st.audit(audit.Base{Event: audit.EventPolicy, Decision: "applied", Approval: st.approver.Mode()}) != nil {
			return nil, "", errApprovalUnrecorded
		}
		if err := config.SaveApproved(st.p, stateDir, key, cur); err != nil {
			return nil, "", st.failed(err)
		}
		return cur, "", nil
	}
	changes := cur.Diff(ap)
	if len(changes) == 0 {
		return ap, "", nil
	}
	if !Loosens(changes) {
		if err := config.SaveApproved(st.p, stateDir, key, cur); err != nil {
			return nil, "", err
		}
		io.Println("policy tightened since the last session:")
		for _, line := range FormatChanges(changes) {
			io.Println(line)
		}
		st.audit(audit.Base{Event: audit.EventPolicy, Decision: "tightened"})
		return cur, "", nil
	}
	io.Println(bold + "The policy of profile " + cur.Profile().Name + " changed since it was approved:" + reset)
	for _, line := range FormatChanges(changes) {
		io.Println(line)
	}
	r := st.decide(ctx, Decision{Prompt: "Apply these changes? [y/N] ", Expected: "y", For: "to apply the policy changes"})
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
	if err := config.SaveApproved(st.p, stateDir, key, cur); err != nil {
		return nil, "", st.failed(err)
	}
	return cur, "", nil
}

// expiringSession is a session whose login expires (a Vault lease).
type expiringSession struct {
	Session
	refreshAt time.Time
}

// CredentialsExpire is when the session must be replaced.
func (s *expiringSession) CredentialsExpire() time.Time { return s.refreshAt }

// connect obtains the credentials of the profile and opens a session. The
// secret is wiped once Connect returns.
func (st *starter) connect(ctx context.Context, first bool) (Session, error) {
	p := st.profile
	open := func(c Credentials) (Session, error) {
		cctx, cancel := context.WithTimeout(ctx, connectTimeout)
		defer cancel()
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

// connectVault connects with the login read from Vault at every
// connection, never stored. The user comes from the secret, or from the
// profile when the secret has none; a secret naming another user than the
// profile is refused.
func (st *starter) connectVault(ctx context.Context, p Profile, open func(Credentials) (Session, error), first bool) (Session, error) {
	fetched := st.o.Now()
	c, err := st.vaultRead(ctx, p.VaultPath)
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

// reconnect opens a new session under p, the profile in force now, and
// runs the checks again with the start-up rules.
func (st *starter) reconnect(ctx context.Context, p Profile) (Session, error) {
	st.profile = p
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
