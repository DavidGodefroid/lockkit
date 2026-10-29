package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/sanitize"
	"github.com/DavidGodefroid/lockkit/ui"
)

// StatusResult answers the status method: the console's part, and the
// product's (Backend.Status) under "product".
type StatusResult struct {
	Profile        string `json:"profile"`
	Production     bool   `json:"production"`
	AutoApprove    bool   `json:"auto_approve"`
	AllowUnmask    bool   `json:"allow_unmask"`
	ShowResults    bool   `json:"show_results"`
	IdleTimeoutInS int    `json:"idle_timeout_in_s"`
	SessionEndsInS int    `json:"session_ends_in_s"`
	// Level is the security level: 0 session shape, 1 or 2 desktop shape.
	Level   int `json:"level"`
	Product any `json:"product,omitempty"`
}

// ServerConfig holds what a Server needs once the start-up sequence is
// done. Run builds it; tests build it directly.
type ServerConfig struct {
	Product kit.Product
	Backend Backend
	// Policy is the approved policy the server enforces.
	Policy Policy
	// StateDir and ApprovedKey locate the approved policy file ("" keeps
	// adoptions in memory).
	StateDir    string
	ApprovedKey string
	Session     Session
	Audit       *audit.Log
	IO          IO
	// Approver takes every human decision; nil means typed approvals.
	Approver Approver
	// Level is the isolation level (2: every decision takes a finger, and
	// a typed answer alone never widens anything).
	Level int
	// Boundary names the desktop boundary for the status screen.
	Boundary string
	Now      func() time.Time
	// Auto, AllowUnmask and ShowResults are the switches at start.
	Auto, AllowUnmask, ShowResults bool
	// Reconnect opens a new session (credentials, Connect, Checks) under
	// the profile in force; nil means a lost connection ends the console.
	Reconnect func(ctx context.Context, p Profile) (Session, error)
	// Quantum levels response times (Env.Level).
	Quantum time.Duration
	// PeerAllowed decides which clients are served; nil: the console's own
	// account.
	PeerAllowed func(ipc.Cred) bool
	// Sanitizer scrubs error text; nil is sanitize.New().
	Sanitizer *sanitize.Sanitizer
	// Refused is the fingerprint of a loosening the human refused at start,
	// not announced again until the files change.
	Refused string
	// RefuseProduction re-applies the start-up refusals of a production
	// profile (an X11 session, core dumps that could not be disabled) when
	// the policy in force becomes production; nil refuses nothing.
	RefuseProduction func() error
}

// Server serves client requests one at a time against one session. It is
// not safe for concurrent use: Serve runs every request on one goroutine.
type Server struct {
	cfg      ServerConfig
	approver Approver
	approved Policy
	profile  Profile
	methods  map[string]Handler
	sess     Session
	now      func() time.Time
	san      *sanitize.Sanitizer

	started, lastSeen, connected time.Time

	auto, showResults, allowUnmask bool

	// pending is a loosening policy read from the files that awaits :review.
	pending *Policy
	// refused is the fingerprint of the last loosening the human refused.
	refused string
	// requests are change.request proposals from clients.
	requests []string
	// lastLoadErr avoids repeating the same config error every poll.
	lastLoadErr string
	// prompting counts the decisions being asked: a control key pressed
	// meanwhile never widens a switch (widenRefused).
	prompting int

	ended  bool
	reason string
}

// The console's own methods: a backend may not take their names.
var ownMethods = []string{ipc.MethodHello, ipc.MethodStatus, ipc.MethodPIIList, ipc.MethodPIIAdd, ipc.MethodChangeRequest, ipc.MethodLogout}

// NewServer checks cfg and returns a server enforcing cfg.Policy.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Backend == nil || cfg.Policy == nil || cfg.IO == nil || cfg.Audit == nil {
		return nil, errors.New("console: server needs a backend, a policy, an IO and an audit log")
	}
	if err := cfg.Product.Validate(); err != nil {
		return nil, err
	}
	if cfg.ShowResults && cfg.Level != 0 {
		return nil, fmt.Errorf("%w: level %d does not accept --show-results", ErrConfig, cfg.Level)
	}
	methods := cfg.Backend.Methods()
	for _, m := range ownMethods {
		if _, ok := methods[m]; ok {
			return nil, fmt.Errorf("console: the backend may not serve the console's method %q", m)
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Approver == nil {
		cfg.Approver = NewTypedApprover(cfg.IO)
	}
	if cfg.Sanitizer == nil {
		cfg.Sanitizer = sanitize.New()
	}
	s := &Server{cfg: cfg, approver: cfg.Approver, methods: methods, sess: cfg.Session, now: cfg.Now, san: cfg.Sanitizer,
		auto: cfg.Auto, showResults: cfg.ShowResults, allowUnmask: cfg.AllowUnmask, refused: cfg.Refused}
	s.apply(cfg.Policy)
	s.started = s.now()
	s.lastSeen, s.connected = s.started, s.started
	if s.autoApprove() {
		s.println(Paint.Yellow("auto mode: requests run without a prompt unless they ask for a human every time (Shift+Tab: manual)"))
	}
	s.refreshStatus()
	return s, nil
}

func (s *Server) apply(p Policy) {
	s.approved = p
	s.profile = p.Profile()
	if s.profile.IdleTimeout <= 0 {
		s.profile.IdleTimeout = 20 * time.Minute
	}
	if s.profile.MaxSession <= 0 {
		s.profile.MaxSession = 4 * time.Hour
	}
}

func (s *Server) println(line string) { s.cfg.IO.Println(line) }

// fingerprintLevel reports level 2: a typed answer alone never widens.
func (s *Server) fingerprintLevel() bool { return s.cfg.Level == 2 }

// level1Window is why level 1 prints nothing in clear.
const level1Window = "the agent's account can read this window"

// record writes the console's own records, through the backend's
// AuditRecord when it has one.
func (s *Server) record(ctx context.Context, b audit.Base) {
	b.Profile = s.profile.Name
	StampPeer(ctx, &b)
	var rec audit.Record = b
	if ar, ok := s.cfg.Backend.(interface{ AuditRecord(audit.Base) audit.Record }); ok {
		rec = ar.AuditRecord(b)
	}
	s.write(rec)
}

func (s *Server) write(rec audit.Record) {
	if err := s.cfg.Audit.Append(rec); err != nil {
		s.println("audit log write failed: " + err.Error())
	}
}

// asker takes the human decisions of s.
func (s *Server) asker() Asker {
	return Asker{IO: s.cfg.IO, Approver: s.approver, Profile: s.profile.Name, Lock: s.cfg.Product.Name, End: s.End,
		Waiting: func(on bool) {
			if on {
				s.prompting++
			} else {
				s.prompting--
			}
		}}
}

// decide asks the approver and explains a missing finger. Too many
// non-matching fingers end the console.
func (s *Server) decide(ctx context.Context, d Decision) Result { return s.asker().Decide(ctx, d) }

// noFingerFields is the audit text of a refusal for want of a finger.
func noFingerFields(r Result) (reason, errText string) {
	if r.Outcome != NoFinger {
		return "", ""
	}
	return "no fingerprint", r.Err.Error()
}

// End stops the session after the current request.
func (s *Server) End(reason string) {
	if !s.ended {
		s.ended, s.reason = true, reason
	}
}

// Ended reports whether the session is over, and why.
func (s *Server) Ended() (string, bool) { return s.reason, s.ended }

// Tick ends the session on idle or maximum session timeout, as set by the
// policy in force.
func (s *Server) Tick() {
	now := s.now()
	switch {
	case now.Sub(s.started) >= s.profile.MaxSession:
		s.End("maximum session length")
	case now.Sub(s.lastSeen) >= s.profile.IdleTimeout:
		s.End("idle timeout")
	}
}

// Close closes the session.
func (s *Server) Close() {
	if s.sess != nil {
		_ = s.sess.Close()
		s.sess = nil
	}
}

// Loop is the request loop of s, for Serve.
func (s *Server) Loop() *Loop {
	return &Loop{IO: s.cfg.IO, Handle: s.Handle, Command: s.Command, Key: s.Key, Tick: s.Tick, Poll: s.CheckPolicy,
		Ended: func() bool { return s.ended }, End: s.End, Refresh: s.refreshStatus, Clear: s.clearStatus,
		PeerAllowed: s.cfg.PeerAllowed}
}

// Handle serves one request. None of the console's methods loosens the
// policy.
func (s *Server) Handle(ctx context.Context, req ipc.Request) ipc.Response {
	s.lastSeen = s.now()
	switch req.Method {
	case ipc.MethodHello:
		return s.hello(req)
	case ipc.MethodStatus:
		return OKResp(req.ID, s.Status())
	case ipc.MethodPIIList:
		return s.piiList(req)
	case ipc.MethodPIIAdd:
		return s.piiAdd(req)
	case ipc.MethodChangeRequest:
		return s.changeRequest(req)
	case ipc.MethodLogout:
		s.println("logout requested by a client")
		s.End("logout")
		return OKResp(req.ID, map[string]bool{"ok": true})
	}
	if h, ok := s.methods[req.Method]; ok {
		return h(ctx, req, s)
	}
	return ErrResp(req.ID, ipc.CodeMethodNotFound, fmt.Sprintf("unknown method %q", req.Method))
}

// Decode decodes the params of req into v, refusing unknown fields; nil
// when they decode (or are absent), else the error response.
func Decode(req ipc.Request, v any) *ipc.Response {
	raw := bytes.TrimSpace(req.Params)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		r := ErrResp(req.ID, ipc.CodeInvalidParams, "invalid params for "+req.Method)
		return &r
	}
	return nil
}

func (s *Server) hello(req ipc.Request) ipc.Response {
	var p ipc.HelloParams
	if r := Decode(req, &p); r != nil {
		return *r
	}
	if !ipc.Compatible(p.ProtocolMajor) {
		return ErrResp(req.ID, ipc.CodeInvalidRequest, fmt.Sprintf(
			"protocol mismatch: client speaks %d, console speaks %d; use the same %s version on both sides",
			p.ProtocolMajor, ipc.ProtocolMajor, s.cfg.Product.Name))
	}
	return OKResp(req.ID, ipc.HelloResult{ProtocolMajor: ipc.ProtocolMajor, ConsoleVersion: s.cfg.Product.Version, Profile: s.profile.Name})
}

// Status is the status method's answer.
func (s *Server) Status() StatusResult {
	left := max(s.profile.MaxSession-s.now().Sub(s.started), 0)
	st := StatusResult{
		Profile: s.profile.Name, Production: s.profile.Production, AutoApprove: s.autoApprove(),
		AllowUnmask: s.allowUnmask, ShowResults: s.showResults, Level: s.cfg.Level,
		IdleTimeoutInS: int(s.profile.IdleTimeout / time.Second), SessionEndsInS: int(left / time.Second),
	}
	if s.sess != nil {
		st.Product = s.cfg.Backend.Status(s.sess)
	}
	return st
}

// maxRequests bounds the queued change requests, maxRequestLen their size.
const (
	maxRequests   = 20
	maxRequestLen = 500
)

func (s *Server) changeRequest(req ipc.Request) ipc.Response {
	var p ipc.ChangeParams
	if r := Decode(req, &p); r != nil {
		return *r
	}
	change := strings.TrimSpace(p.Change)
	if change == "" || len(change) > maxRequestLen {
		return ErrResp(req.ID, ipc.CodeInvalidParams, fmt.Sprintf("change must be 1 to %d bytes", maxRequestLen))
	}
	if len(s.requests) >= maxRequests {
		return ErrResp(req.ID, ipc.CodeInvalidRequest, "too many pending change requests; the human reviews them with :review")
	}
	change = sanitize.Terminal(change, false)
	s.requests = append(s.requests, change)
	s.println(Paint.Warn("change request from a client: " + change + " (:review)"))
	s.refreshStatus()
	return OKResp(req.ID, ipc.ChangeResult{Queued: true})
}

// piiBackend returns the backend's PII side, or the answer of a product
// without mask rules.
func (s *Server) piiBackend(req ipc.Request) (PIIBackend, *ipc.Response) {
	pb, ok := s.cfg.Backend.(PIIBackend)
	if !ok {
		r := ErrResp(req.ID, ipc.CodeMethodNotFound, s.cfg.Product.Name+" has no PII rules")
		return nil, &r
	}
	return pb, nil
}

func (s *Server) piiResult(pb PIIBackend) ipc.PIIListResult {
	mask, allow := pb.PIIRules(s.approved)
	return ipc.PIIListResult{Mask: nonNil(mask), Allow: nonNil(allow)}
}

func (s *Server) piiList(req ipc.Request) ipc.Response {
	pb, r := s.piiBackend(req)
	if r != nil {
		return *r
	}
	return OKResp(req.ID, s.piiResult(pb))
}

// piiAdd adds a mask rule: to the file, to the policy in force, and to a
// pending loosening, which was read before the rule reached the file and
// would otherwise drop it once applied from :review.
func (s *Server) piiAdd(req ipc.Request) ipc.Response {
	pb, r := s.piiBackend(req)
	if r != nil {
		return *r
	}
	var p ipc.PIIAddParams
	if r := Decode(req, &p); r != nil {
		return *r
	}
	pattern, err := pb.CheckMask(p.Pattern)
	if err != nil {
		return ErrResp(req.ID, ipc.CodeInvalidParams, s.san.Error(err))
	}
	if err := pb.SaveMask(pattern); err != nil {
		return ErrResp(req.ID, ipc.CodeInternal, s.san.Error(err))
	}
	if err := s.adopt(pb.WithMask(s.approved, pattern), "tightened"); err != nil {
		return ErrResp(req.ID, ipc.CodeInternal, s.san.Error(err))
	}
	if s.pending != nil {
		next := pb.WithMask(*s.pending, pattern)
		s.pending = &next
	}
	s.println("PII rule added by a client: mask " + sanitize.Terminal(pattern, false))
	return OKResp(req.ID, s.piiResult(pb))
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Env.

// Auto implements Env.
func (s *Server) Auto() bool { return s.autoApprove() }

// ShowResults implements Env.
func (s *Server) ShowResults() bool { return s.showResults }

// UnmaskAllowed implements Env.
func (s *Server) UnmaskAllowed() bool { return s.allowUnmask }

// Policy implements Env.
func (s *Server) Policy() Policy { return s.approved }

// Audit implements Env.
func (s *Server) Audit(rec audit.Record) { s.write(rec) }

// AuditBase implements Env.
func (s *Server) AuditBase(ctx context.Context, b audit.Base) { s.record(ctx, b) }

// Println implements Env.
func (s *Server) Println(line string) { s.println(line) }

// Safe implements Env.
func (s *Server) Safe(text string) string { return sanitize.Terminal(text, false) }

// Sanitizer implements Env.
func (s *Server) Sanitizer() *sanitize.Sanitizer { return s.san }

// Level implements Env.
func (s *Server) Level(ctx context.Context, start time.Time) { Level(ctx, s.cfg.Quantum, start) }

// Lost implements Env.
func (s *Server) Lost() { s.Close() }

// Session implements Env.
func (s *Server) Session(ctx context.Context) (Session, error) {
	if ttl := s.profile.CredentialsTTL; s.sess != nil && ttl > 0 && s.now().Sub(s.connected) >= ttl {
		s.println(fmt.Sprintf("credentials_ttl (%s) reached: the connection is closed and the secret asked again", ttl))
		s.Close()
	} else if e, ok := s.sess.(interface{ CredentialsExpire() time.Time }); ok && !e.CredentialsExpire().IsZero() && !s.now().Before(e.CredentialsExpire()) {
		s.println("the Vault lease of the login is ending: the connection is closed and a fresh login read from Vault")
		s.Close()
	}
	if s.sess != nil {
		return s.sess, nil
	}
	if s.cfg.Reconnect == nil {
		s.End("connection lost")
		return nil, errors.New("console: the connection is lost; the human must restart the console")
	}
	s.println("reconnecting…")
	sess, err := s.cfg.Reconnect(ctx, s.profile)
	if err != nil {
		s.println("reconnect failed: " + sanitize.Terminal(s.san.Error(err), false))
		if errors.Is(err, errReconnectRefused) || errors.Is(err, ErrTooManyNoMatch) {
			s.End("reconnect refused")
		}
		return nil, errors.New("console: the connection is lost; the human must restart the console")
	}
	s.sess, s.connected = sess, s.now()
	return sess, nil
}

// errReconnectRefused marks a reconnection stopped by the checks.
var errReconnectRefused = errors.New("console: reconnection refused by the checks")

// frameColour is the colour of the approval frame.
func (s *Server) frameColour(sc Screen) string {
	if s.profile.Production || sc.Production || sc.Red {
		return ui.Red
	}
	return ui.Violet
}

// Approve implements Env: it frames sc, approves it in auto mode or asks
// the human, and audits the decision.
func (s *Server) Approve(ctx context.Context, id int64, sc Screen) Approval {
	frame := s.frameColour(sc)
	sep := Paint.Dim(" · ")
	bar := Paint.Paint(frame, "│ ")
	s.println("")
	head := Paint.Paint(frame, "╭─ ") + Paint.Paint(bold+frame, strings.ToUpper(s.profile.Name))
	if sc.Header != "" {
		head += sep + sanitize.Terminal(sc.Header, false)
	}
	s.println(head + " " + Paint.Paint(frame, "─────"))
	who := sc.Requester
	if who == "" {
		who = PeerText(ctx)
	}
	if who != "" {
		s.println(bar + Paint.Dim("requested by "+sanitize.Terminal(who, false)))
	}
	if sc.Note != "" {
		s.println(bar + Paint.Dim("agent: "+sanitize.Terminal(sc.Note, false)))
	}
	s.println(Paint.Paint(frame, "│"))
	for _, l := range sc.Body {
		if l == "" {
			s.println(Paint.Paint(frame, "│"))
			continue
		}
		s.println(bar + sanitize.Terminal(l, false))
	}
	for _, w := range sc.Warnings {
		s.println(bar + red + "▲ " + sanitize.Terminal(w, false) + reset)
	}
	base := audit.Base{Intent: sc.Note, Warnings: sc.Warnings}
	rec := func(b audit.Base) {
		b.Profile = s.profile.Name
		StampPeer(ctx, &b)
		if sc.Record != nil {
			s.write(sc.Record(b))
			return
		}
		s.record(context.Background(),b)
	}

	production := s.profile.Production || sc.Production
	if s.autoApprove() && !production && !sc.NeverAuto {
		s.println(Paint.Paint(frame, "╰─ ") + Paint.Yellow("auto-approved") + Paint.Dim(" (auto mode)"))
		b := base
		b.Event, b.Decision = audit.EventAuto, "auto"
		rec(b)
		return Approval{Approved: true, Auto: true}
	}
	q := Ask{Frame: frame, Production: production, Retype: sc.Retype, Screen: &sc}
	return s.asker().Ask(ctx, id, q, func(d audit.Base) {
		b := base
		b.Event, b.Decision, b.Reason, b.Error, b.Approval = d.Event, d.Decision, d.Reason, d.Error, d.Approval
		rec(b)
	})
}

// maxDenyReason bounds the reason given with a denial.
const maxDenyReason = 200

// DenyReason is the reason of an answer "n <text>" or "no <text>" (n and
// no in any case), trimmed, cut at 200 bytes and escaped; "" for any other
// answer.
func DenyReason(ans string) string {
	word, text, ok := strings.Cut(strings.TrimSpace(ans), " ")
	if !ok || (!strings.EqualFold(word, "n") && !strings.EqualFold(word, "no")) {
		return ""
	}
	text = strings.TrimSpace(text)
	if len(text) > maxDenyReason {
		cut := maxDenyReason
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text = text[:cut]
	}
	return sanitize.Terminal(text, false)
}

// Policy review.

// CheckPolicy re-reads the policy from the config files. Changes that only
// tighten are applied at once; a loosening waits for :review.
func (s *Server) CheckPolicy() {
	cur, err := s.cfg.Backend.LoadPolicy()
	if err != nil {
		msg := "config error: " + sanitize.Terminal(err.Error(), false) + "; the last approved policy stays in force"
		if msg != s.lastLoadErr {
			s.lastLoadErr = msg
			s.println(msg)
		}
		return
	}
	s.lastLoadErr = ""
	fp := config.Fingerprint(cur)
	switch {
	case fp == config.Fingerprint(s.approved):
		s.pending, s.refused = nil, ""
		return
	case s.pending != nil && fp == config.Fingerprint(*s.pending), fp == s.refused:
		return
	}
	changes := cur.Diff(s.approved)
	if !Loosens(changes) {
		s.pending = nil
		if err := s.adopt(cur, "tightened"); err != nil {
			s.println("policy change not applied: " + sanitize.Terminal(err.Error(), false))
			return
		}
		s.println("policy tightened:")
		for _, line := range FormatChanges(changes) {
			s.println(line)
		}
		return
	}
	s.pending = &cur
	s.println(red + "pending policy change (loosening) — type :review to see it" + reset)
	s.refreshStatus()
}

// PolicyPending reports a loosening awaiting :review: a product refuses
// requests meanwhile (ipc.CodePolicyPending) when its policy matters to
// them.
func (s *Server) PolicyPending() bool { return s.pending != nil }

// Loosens reports whether any change loosens the policy.
func Loosens(changes []config.Change) bool {
	return slices.ContainsFunc(changes, func(c config.Change) bool { return c.Loosens })
}

// adopt records p as the approved policy and enforces it. A change of
// where the backend is ends the session: the open connection no longer
// matches the policy.
func (s *Server) adopt(p Policy, decision string) error {
	if s.cfg.StateDir != "" && s.cfg.ApprovedKey != "" {
		if err := config.SaveApproved(s.cfg.Product, s.cfg.StateDir, s.cfg.ApprovedKey, p); err != nil {
			return err
		}
	}
	old := s.profile
	s.apply(p)
	b := audit.Base{Event: audit.EventPolicy, Decision: decision}
	if decision == "applied" {
		b.Approval = s.approver.Mode()
	}
	s.record(context.Background(),b)
	n := s.profile
	if n.Production && !old.Production && s.cfg.RefuseProduction != nil {
		if err := s.cfg.RefuseProduction(); err != nil {
			s.println(red + "the profile is now production: " + sanitize.Terminal(err.Error(), false) + "; the session ends" + reset)
			s.End("refused after the profile became production")
			return nil
		}
	}
	if n.Production && !old.Production && s.sess != nil {
		// The start-up checks accepted findings with a typed "continue"; a
		// production profile refuses them.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		findings := s.cfg.Backend.Checks(ctx, s.sess)
		cancel()
		if len(findings) > 0 {
			s.println(red + "the profile is now production and the checks found: " + sanitize.Terminal(findings[0].Text, false) + "; the session ends" + reset)
			s.End("checks failed after the profile became production")
			return nil
		}
	}
	if old.Where != n.Where || old.User != n.User || old.Host != n.Host || old.Port != n.Port {
		s.println("connection settings changed: the session ends; start the console again")
		s.End("connection settings changed")
	}
	return nil
}

// FormatChanges renders a policy diff, loosenings in red. Every value is
// escaped: a pattern or a host could otherwise carry terminal escapes that
// hide a loosening from the human.
func FormatChanges(changes []config.Change) []string {
	var out []string
	for _, c := range changes {
		c.Field, c.Old, c.New = sanitize.Terminal(c.Field, false), sanitize.Terminal(c.Old, false), sanitize.Terminal(c.New, false)
		var line string
		switch {
		case c.Old == "":
			line = fmt.Sprintf("  + %s: %s", c.Field, c.New)
		case c.New == "":
			line = fmt.Sprintf("  - %s: %s", c.Field, c.Old)
		default:
			line = fmt.Sprintf("  ~ %s: %s → %s", c.Field, c.Old, c.New)
		}
		if c.Loosens {
			line = red + line + "  (loosens)" + reset
		} else {
			line = green + line + reset
		}
		out = append(out, line)
	}
	return out
}

// review shows the queued change requests and the pending policy change,
// and asks the human to apply the latter.
func (s *Server) review(ctx context.Context) {
	if len(s.requests) == 0 && s.pending == nil {
		s.println("nothing to review")
		return
	}
	if len(s.requests) > 0 {
		s.println("change requests from clients (edit the config files to apply one; " + s.cfg.Product.Name + " then asks you to confirm):")
		for _, r := range s.requests {
			s.println("  - " + r)
		}
		s.requests = nil
	}
	if s.pending == nil {
		return
	}
	next := *s.pending
	s.println("pending policy change for profile " + s.profile.Name + ":")
	for _, line := range FormatChanges(next.Diff(s.approved)) {
		s.println(line)
	}
	if s.auto && s.profile.Production && !next.Profile().Production {
		s.println(red + "auto mode is on: once applied, requests run without a prompt" + reset)
	}
	Bell(s.cfg.IO)
	r := s.decide(ctx, Decision{Prompt: "Apply these changes? [y/N] ", Expected: "y", For: "to apply the policy changes"})
	s.pending = nil
	if r.Outcome != Approved {
		s.refused = config.Fingerprint(next)
		reason, errText := noFingerFields(r)
		s.record(context.Background(),audit.Base{Event: audit.EventPolicy, Decision: "refused", Reason: reason, Error: errText})
		s.println("policy change refused: the last approved policy stays in force")
		return
	}
	s.refused = ""
	if err := s.adopt(next, "applied"); err != nil {
		s.println("policy change not applied: " + sanitize.Terminal(err.Error(), false))
		return
	}
	s.println("policy change applied")
}

// newPolicyLike returns a pointer to a new zero value of p's dynamic type,
// to decode an approved policy into.
func newPolicyLike(p Policy) any {
	t := reflect.TypeOf(p)
	if t.Kind() == reflect.Pointer {
		return reflect.New(t.Elem()).Interface()
	}
	return reflect.New(t).Interface()
}

// policyFrom turns what newPolicyLike decoded back into a Policy of p's
// dynamic type.
func policyFrom(p Policy, v any) (Policy, bool) {
	if reflect.TypeOf(p).Kind() == reflect.Pointer {
		q, ok := v.(Policy)
		return q, ok
	}
	q, ok := reflect.ValueOf(v).Elem().Interface().(Policy)
	return q, ok
}
