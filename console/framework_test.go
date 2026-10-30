//go:build unix

package console

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/fingerprint"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/secrets"
	"github.com/DavidGodefroid/lockkit/sysconf"
)

// fakePolicy is a product policy with locksql-like semantics: a tier
// (read < peek), a production flag, a row limit and the shared base.
type fakePolicy struct {
	Name       string      `json:"name"`
	Host       string      `json:"host"`
	Tier       string      `json:"tier"`
	Production bool        `json:"production"`
	MaxRows    int         `json:"max_rows"`
	Base       config.Base `json:"base"`
}

var tierRank = map[string]int{"read": 0, "peek": 1}

func (p fakePolicy) Diff(approved config.Policy) []config.Change {
	a := approved.(fakePolicy)
	var out []config.Change
	if a.Tier != p.Tier {
		out = append(out, config.Change{Field: "tier", Old: a.Tier, New: p.Tier, Loosens: tierRank[p.Tier] > tierRank[a.Tier]})
	}
	if a.Production != p.Production {
		out = append(out, config.Change{Field: "production", Old: strconv.FormatBool(a.Production), New: strconv.FormatBool(p.Production), Loosens: a.Production})
	}
	if a.MaxRows != p.MaxRows {
		out = append(out, config.Change{Field: "limits.max_rows", Old: strconv.Itoa(a.MaxRows), New: strconv.Itoa(p.MaxRows),
			Loosens: config.LooserLimit(int64(a.MaxRows), int64(p.MaxRows))})
	}
	if a.Host != p.Host {
		out = append(out, config.Change{Field: "host", Old: a.Host, New: p.Host, Loosens: true})
	}
	return append(out, config.DiffBase(a.Base, p.Base)...)
}

func (p fakePolicy) Describe() []string {
	return []string{fmt.Sprintf("tier %s · production %t · max_rows %d", p.Tier, p.Production, p.MaxRows)}
}

func (p fakePolicy) Profile() Profile {
	return Profile{Name: p.Name, Production: p.Production, Where: p.Host + ":5671", Host: p.Host, Port: 5671, DefaultPort: 5671,
		User: p.Base.User, Credentials: p.Base.Credentials, VaultPath: p.Base.VaultPath, CredentialsTTL: p.Base.CredentialsTTL,
		IdleTimeout: p.Base.IdleTimeout, MaxSession: p.Base.MaxSession}
}

func uat() fakePolicy {
	return fakePolicy{Name: "uat", Host: "broker.example.com", Tier: "read", MaxRows: 20,
		Base: config.Base{User: "ro", Credentials: config.CredentialsAsk, IdleTimeout: 20 * time.Minute, MaxSession: 4 * time.Hour}}
}

func prod() fakePolicy {
	p := uat()
	p.Name, p.Production = "prod", true
	return p
}

type fakeSession struct {
	mu     sync.Mutex
	closed bool
}

func (s *fakeSession) Close() error { s.mu.Lock(); defer s.mu.Unlock(); s.closed = true; return nil }

// fakeBackend serves "op.read": a screen, then the value if approved.
type fakeBackend struct {
	mu       sync.Mutex
	policy   fakePolicy
	loadErr  error
	findings []Finding
	creds    []Credentials
	connErr  error
	sessions []*fakeSession
}

func (b *fakeBackend) Methods() map[string]Handler {
	return map[string]Handler{"op.read": func(ctx context.Context, req ipc.Request, env Env) ipc.Response {
		var p struct {
			Queue     string `json:"queue"`
			Note      string `json:"note"`
			NeverAuto bool   `json:"never_auto"`
			// BadRecord makes the screen's Record return no record.
			BadRecord bool `json:"bad_record"`
		}
		if r := Decode(req, &p); r != nil {
			return *r
		}
		if _, err := env.Session(ctx); err != nil {
			return ErrResp(req.ID, ipc.CodeConnLost, err.Error())
		}
		sc := Screen{Header: "broker.example.com / orders", Note: p.Note,
			Body: []string{"READ " + p.Queue}, NeverAuto: p.NeverAuto, Warnings: []string{"not read-only"}}
		if p.BadRecord {
			sc.Record = func(audit.Base) audit.Record { return nil }
		}
		a := env.Approve(ctx, req.ID, sc)
		if !a.Approved {
			return a.Refusal
		}
		return OKResp(req.ID, map[string]any{"messages": 1, "auto": a.Auto})
	}}
}

func (b *fakeBackend) Connect(_ context.Context, c Credentials) (Session, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.creds = append(b.creds, Credentials{User: c.User, Secret: append([]byte(nil), c.Secret...), Policy: c.Policy})
	if b.connErr != nil {
		return nil, b.connErr
	}
	s := &fakeSession{}
	b.sessions = append(b.sessions, s)
	return s, nil
}

func (b *fakeBackend) Checks(context.Context, Session) []Finding { return b.findings }

func (b *fakeBackend) LoadPolicy() (Policy, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.loadErr != nil {
		return nil, b.loadErr
	}
	return b.policy, nil
}

func (b *fakeBackend) Status(Session) any { return map[string]string{"tier": b.policy.Tier} }

type harness struct {
	s     *Server
	b     *fakeBackend
	io    *fakeIO
	state string
	log   string
}

func newHarness(t *testing.T, p fakePolicy, mutate func(*ServerConfig)) *harness {
	t.Helper()
	state := t.TempDir()
	log, err := audit.Open(testProduct, state)
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{policy: p}
	io := &fakeIO{}
	cfg := ServerConfig{Product: testProduct, Backend: b, Policy: p, StateDir: state, ApprovedKey: "user-" + p.Name,
		Session: &fakeSession{}, Audit: log, IO: io}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{s: s, b: b, io: io, state: state, log: log.Path()}
}

func (h *harness) call(t *testing.T, ctx context.Context, method string, params any) ipc.Response {
	t.Helper()
	raw, _ := json.Marshal(params)
	return h.s.Handle(ctx, ipc.Request{JSONRPC: "2.0", ID: 7, Method: method, Params: raw})
}

func (h *harness) records(t *testing.T) []map[string]any {
	t.Helper()
	f, err := os.Open(h.log)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func (h *harness) lastRecord(t *testing.T) map[string]any {
	t.Helper()
	recs := h.records(t)
	if len(recs) == 0 {
		t.Fatal("no audit record")
	}
	return recs[len(recs)-1]
}

func TestNewServerRefusesTakingConsoleMethods(t *testing.T) {
	log, _ := audit.Open(testProduct, t.TempDir())
	b := &badBackend{}
	if _, err := NewServer(ServerConfig{Product: testProduct, Backend: b, Policy: uat(), Audit: log, IO: &fakeIO{}}); err == nil {
		t.Fatal("a backend serving logout accepted")
	}
}

type badBackend struct{ fakeBackend }

func (*badBackend) Methods() map[string]Handler {
	return map[string]Handler{ipc.MethodLogout: func(context.Context, ipc.Request, Env) ipc.Response { return ipc.Response{} }}
}

func TestHelloStatusLogoutAndUnknown(t *testing.T) {
	h := newHarness(t, uat(), nil)
	r := h.call(t, context.Background(), ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor, Client: "lockmq"})
	var hr ipc.HelloResult
	if r.Error != nil || json.Unmarshal(r.Result, &hr) != nil || hr.Profile != "uat" || hr.ConsoleVersion != "0.1.0" {
		t.Fatalf("hello: %+v", r)
	}
	if r := h.call(t, context.Background(), ipc.MethodHello, ipc.HelloParams{ProtocolMajor: 9}); r.Error == nil || !strings.Contains(r.Error.Message, "same lockmq version") {
		t.Fatalf("mismatch: %+v", r.Error)
	}
	r = h.call(t, context.Background(), ipc.MethodStatus, nil)
	var st StatusResult
	if json.Unmarshal(r.Result, &st) != nil || st.Profile != "uat" || st.Production || st.IdleTimeoutInS != 1200 || st.SessionEndsInS <= 0 {
		t.Fatalf("status: %s", r.Result)
	}
	if !strings.Contains(string(r.Result), `"product":{"tier":"read"}`) {
		t.Fatalf("product status missing: %s", r.Result)
	}
	if r := h.call(t, context.Background(), "op.nope", nil); r.Error == nil || r.Error.Code != ipc.CodeMethodNotFound {
		t.Fatalf("unknown: %+v", r)
	}
	if r := h.call(t, context.Background(), ipc.MethodLogout, nil); r.Error != nil {
		t.Fatal(r.Error)
	}
	if reason, ended := h.s.Ended(); !ended || reason != "logout" {
		t.Fatalf("ended %v %q", ended, reason)
	}
}

func TestApproveManualYes(t *testing.T) {
	h := newHarness(t, uat(), nil)
	h.io.answers = []string{"y"}
	ctx := WithPeer(context.Background(), ipc.Cred{UID: os.Getuid(), PID: os.Getpid()})
	r := h.call(t, ctx, "op.read", map[string]string{"queue": "orders.failed", "note": "why it fails"})
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	out := h.io.plain()
	for _, want := range []string{"╭─ UAT · broker.example.com / orders", "requested by uid", "agent: why it fails", "│ READ orders.failed", "▲ not read-only", "Approve? [y/N]"} {
		if !strings.Contains(out+strings.Join(h.io.promptList(), "\n"), want) {
			t.Errorf("screen lacks %q:\n%s\nprompts %q", want, out, h.io.promptList())
		}
	}
	rec := h.lastRecord(t)
	if rec["event"] != "approved" || rec["approval"] != "session" || rec["intent"] != "why it fails" || rec["profile"] != "uat" || rec["peer_uid"] == nil {
		t.Fatalf("audit: %v", rec)
	}
}

func TestApproveDeniedWithReasonTimeoutAndGone(t *testing.T) {
	h := newHarness(t, uat(), nil)
	h.io.answers = []string{"n not now \x1b[2J"}
	r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "q"})
	if r.Error == nil || r.Error.Code != ipc.CodeDenied || r.Error.Message != `denied by the human: not now \x1b[2J; do not retry unless asked` {
		t.Fatalf("denied: %+v", r.Error)
	}
	if rec := h.lastRecord(t); rec["event"] != "denied" || rec["reason"] != `not now \x1b[2J` {
		t.Fatalf("audit: %v", rec)
	}
	h.io.timeout = true
	if r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "q"}); r.Error == nil || r.Error.Code != ipc.CodeTimeout {
		t.Fatalf("timeout: %+v", r.Error)
	}
	if rec := h.lastRecord(t); rec["event"] != "timeout" {
		t.Fatalf("audit: %v", rec)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := h.call(t, ctx, "op.read", map[string]string{"queue": "q"}); r.Error == nil || r.Error.Code != ipc.CodeDenied || r.Error.Message != "the request was cancelled" {
		t.Fatalf("gone: %+v", r.Error)
	}
	if rec := h.lastRecord(t); rec["event"] != "abandoned" {
		t.Fatalf("audit: %v", rec)
	}
}

// An approval that cannot be audited is refused (fail closed); three
// failed writes in a row end the session.
func TestApproveAuditFailureRefuses(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes a read-only file")
	}
	h := newHarness(t, uat(), nil)
	// A product record that is no record.
	h.io.answers = []string{"y"}
	r := h.call(t, context.Background(), "op.read", map[string]any{"queue": "q", "bad_record": true})
	if r.Error == nil || r.Error.Code != ipc.CodeInternal || !strings.Contains(r.Error.Message, "could not record the approval") {
		t.Fatalf("bad record approved: %s %+v", r.Result, r.Error)
	}
	if !strings.Contains(h.io.plain(), "audit log write failed") || !strings.Contains(h.io.plain(), "refused: the approval could not be recorded") {
		t.Fatalf("the human was not told:\n%s", h.io.plain())
	}
	// A write that succeeds resets the count.
	h.io.answers = []string{"y"}
	if r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "q"}); r.Error != nil {
		t.Fatal(r.Error)
	}
	// An unwritable log: manual and auto approvals are refused.
	if err := os.Chmod(h.log, 0o400); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(h.log, 0o600)
	h.io.answers = []string{"y"}
	if r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "q"}); r.Error == nil || r.Error.Code != ipc.CodeInternal {
		t.Fatalf("unwritable log approved: %s %+v", r.Result, r.Error)
	}
	h.s.auto = true
	if r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "q"}); r.Error == nil || r.Error.Code != ipc.CodeInternal {
		t.Fatalf("unwritable log auto-approved: %s %+v", r.Result, r.Error)
	}
	if _, ended := h.s.Ended(); ended {
		t.Fatal("ended after two failures")
	}
	// A denial stays a denial; the third failure in a row ends the session.
	h.s.auto = false
	h.io.answers = []string{"n"}
	if r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "q"}); r.Error == nil || r.Error.Code != ipc.CodeDenied {
		t.Fatalf("denial: %+v", r.Error)
	}
	if reason, ended := h.s.Ended(); !ended || reason != "the audit log cannot be written" {
		t.Fatalf("session not ended: %q %v", reason, ended)
	}
}

// On production the profile name is typed, exactly; "y" is a denial.
func TestApproveProductionTypedName(t *testing.T) {
	h := newHarness(t, prod(), nil)
	h.io.answers = []string{"y"}
	if r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "q"}); r.Error == nil || r.Error.Code != ipc.CodeDenied {
		t.Fatalf("y approved production: %+v", r)
	}
	h.io.answers = []string{"PROD", "prod"}
	if r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "q"}); r.Error == nil {
		t.Fatal("wrong case approved")
	}
	if r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "q"}); r.Error != nil {
		t.Fatal(r.Error)
	}
	if p := h.io.promptList(); !strings.Contains(p[len(p)-1], `Type the profile name "prod" to approve`) {
		t.Fatalf("prompt %q", p[len(p)-1])
	}
}

// Auto mode approves without a prompt, except a NeverAuto screen and
// never on production.
func TestAutoMode(t *testing.T) {
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Auto = true })
	r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "q"})
	if r.Error != nil || !strings.Contains(string(r.Result), `"auto":true`) || h.io.promptCount() != 0 {
		t.Fatalf("auto: %s %+v prompts %d", r.Result, r.Error, h.io.promptCount())
	}
	if rec := h.lastRecord(t); rec["event"] != "auto" {
		t.Fatalf("audit: %v", rec)
	}
	h.io.answers = []string{"y"}
	if r := h.call(t, context.Background(), "op.read", map[string]any{"queue": "q", "never_auto": true}); r.Error != nil || strings.Contains(string(r.Result), `"auto":true`) || h.io.promptCount() != 1 {
		t.Fatalf("never auto: %s prompts %d", r.Result, h.io.promptCount())
	}
	hp := newHarness(t, prod(), func(c *ServerConfig) { c.Auto = true })
	hp.io.timeout = true
	if r := hp.call(t, context.Background(), "op.read", map[string]string{"queue": "q"}); r.Error == nil || hp.io.promptCount() != 1 {
		t.Fatalf("auto on production: %+v", r)
	}
	if hp.s.Auto() {
		t.Error("Auto() on production")
	}
}

func TestKeysAndCommands(t *testing.T) {
	h := newHarness(t, uat(), nil)
	h.s.Key(KeyShiftTab)
	if !h.s.Auto() || !strings.Contains(h.io.statusLine(), "AUTO") {
		t.Fatalf("Shift+Tab: auto %v status %q", h.s.Auto(), h.io.statusLine())
	}
	if rec := h.lastRecord(t); rec["event"] != "mode" || rec["decision"] != "auto" {
		t.Fatalf("audit: %v", rec)
	}
	h.s.Key(KeyCtrlO)
	if !h.s.ShowResults() || !strings.Contains(h.io.statusLine(), "results clear") {
		t.Fatalf("Ctrl-O: %v %q", h.s.ShowResults(), h.io.statusLine())
	}
	h.io.answers = []string{"n"}
	h.s.Command(context.Background(), ":unmask")
	if h.s.UnmaskAllowed() {
		t.Fatal("unmask allowed on a no")
	}
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":unmask")
	if !h.s.UnmaskAllowed() || !strings.Contains(h.io.statusLine(), "unmask allowed") {
		t.Fatal("unmask not allowed on a yes")
	}
	h.s.Command(context.Background(), ":status")
	if !strings.Contains(h.io.plain(), "tier read · production false · max_rows 20") {
		t.Errorf(":status lacks the policy:\n%s", h.io.plain())
	}
	h.s.Command(context.Background(), ":what")
	if !strings.Contains(h.io.plain(), "commands: :review") {
		t.Error("no help")
	}
	h.s.Command(context.Background(), ":quit")
	if reason, ended := h.s.Ended(); !ended || reason != "quit" {
		t.Fatal(":quit")
	}
	hp := newHarness(t, prod(), nil)
	hp.s.Key(KeyShiftTab)
	if hp.s.Auto() || !strings.Contains(hp.io.plain(), "not available on a production profile") {
		t.Fatal("auto on production")
	}
}

// At level 2 a typed answer alone never widens: auto mode takes a finger,
// the clear results stay off.
func TestLevel2Widening(t *testing.T) {
	v := &fingerprint.Fake{Results: []error{fingerprint.ErrNoMatch}}
	var io *fakeIO
	h := newHarness(t, uat(), func(c *ServerConfig) {
		io = c.IO.(*fakeIO)
		c.Level = 2
		c.Approver = NewFingerprintApprover(io, v, "", time.Second)
	})
	io.answers = []string{"y"}
	h.s.Key(KeyShiftTab)
	if h.s.Auto() || v.Calls != 1 {
		t.Fatalf("auto without a finger: auto %v calls %d", h.s.Auto(), v.Calls)
	}
	h.s.Key(KeyCtrlO)
	if h.s.ShowResults() {
		t.Fatal("clear results at level 2")
	}
}

// keyApprover presses keys while the first decision is asked, then answers
// it.
type keyApprover struct {
	Approver
	during func()
}

func (a *keyApprover) Approve(ctx context.Context, d Decision) Result {
	if f := a.during; f != nil {
		a.during = nil
		f()
	}
	return a.Approver.Approve(ctx, d)
}

// A control key pressed while a prompt waits never widens a switch: at
// level 2 no second finger prompt nests in the pending one.
func TestNoWideningWhilePromptWaits(t *testing.T) {
	v := &fingerprint.Fake{}
	var h *harness
	h = newHarness(t, uat(), func(c *ServerConfig) {
		c.Level = 2
		c.Approver = &keyApprover{Approver: NewFingerprintApprover(c.IO, v, "left-index-finger", time.Second), during: func() { h.s.Key(KeyShiftTab) }}
	})
	h.io.answers = []string{"y"}
	if r := h.call(t, context.Background(), "op.read", map[string]any{"queue": "q"}); r.Error != nil {
		t.Fatalf("request: %+v", r.Error)
	}
	if h.s.Auto() || v.Calls != 1 || !strings.Contains(h.io.plain(), "auto mode: not while a prompt waits") {
		t.Fatalf("auto %v, finger calls %d:\n%s", h.s.Auto(), v.Calls, h.io.plain())
	}
	if !strings.Contains(h.io.plain(), "Place your left index finger on the reader to approve the request above") {
		t.Fatalf("the finger prompt does not name its decision:\n%s", h.io.plain())
	}

	var h0 *harness
	h0 = newHarness(t, uat(), func(c *ServerConfig) {
		c.Approver = &keyApprover{Approver: NewTypedApprover(c.IO), during: func() {
			h0.s.Key(KeyShiftTab)
			h0.s.Key(KeyCtrlO)
			h0.s.Command(context.Background(), ":unmask")
		}}
	})
	h0.io.answers = []string{"y"}
	if r := h0.call(t, context.Background(), "op.read", map[string]any{"queue": "q"}); r.Error != nil {
		t.Fatalf("request: %+v", r.Error)
	}
	if h0.s.Auto() || h0.s.ShowResults() || h0.s.UnmaskAllowed() {
		t.Fatalf("widened during a prompt: auto %v results %v unmask %v", h0.s.Auto(), h0.s.ShowResults(), h0.s.UnmaskAllowed())
	}
	if n := strings.Count(h0.io.plain(), "not while a prompt waits"); n != 3 {
		t.Fatalf("refusal printed %d times:\n%s", n, h0.io.plain())
	}
	// Between prompts the keys work again.
	h0.s.Key(KeyShiftTab)
	if !h0.s.Auto() {
		t.Fatal("auto mode refused with no prompt waiting")
	}
}

// Narrowing stays allowed while a prompt waits: auto mode can be switched
// off during a request that asks for a human every time.
func TestNarrowingWhilePromptWaits(t *testing.T) {
	var h *harness
	h = newHarness(t, uat(), func(c *ServerConfig) {
		c.Auto = true
		c.Approver = &keyApprover{Approver: NewTypedApprover(c.IO), during: func() { h.s.Key(KeyShiftTab) }}
	})
	h.io.answers = []string{"y"}
	if r := h.call(t, context.Background(), "op.read", map[string]any{"queue": "q", "never_auto": true}); r.Error != nil {
		t.Fatalf("request: %+v", r.Error)
	}
	if h.s.Auto() {
		t.Fatal("auto mode not switched off during a prompt")
	}
}

// At level 1 the agent's account can read the console window: Ctrl-O and
// :results leave the results masked, with nothing audited, while auto mode
// and :unmask still work as at level 0.
func TestLevel1ClearResultsRefused(t *testing.T) {
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Level = 1 })
	before := len(h.records(t))
	h.s.Key(KeyCtrlO)
	h.s.Command(context.Background(), ":results")
	if h.s.ShowResults() || !strings.Contains(h.io.statusLine(), "results masked") {
		t.Fatalf("clear results at level 1: %v %q", h.s.ShowResults(), h.io.statusLine())
	}
	if n := strings.Count(h.io.plain(), "results stay masked at level 1: the agent's account can read this window"); n != 2 {
		t.Fatalf("refusal printed %d times:\n%s", n, h.io.plain())
	}
	for _, rec := range h.records(t)[before:] {
		if rec["event"] == "results" {
			t.Fatalf("refused switch audited: %v", rec)
		}
	}
	h.s.Command(context.Background(), ":status")
	if !strings.Contains(h.io.plain(), "masked (the agent's view)") {
		t.Errorf(":status:\n%s", h.io.plain())
	}
	if st := h.s.Status(); st.ShowResults || st.Level != 1 {
		t.Errorf("status = %+v", st)
	}
	h.s.Key(KeyShiftTab)
	if !h.s.Auto() {
		t.Error("auto mode refused at level 1")
	}
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":unmask")
	if !h.s.UnmaskAllowed() {
		t.Error("unmask refused at level 1")
	}
}

// ShowResults at start is refused by NewServer at levels 1 and 2, whoever
// assembles the console; Auto and AllowUnmask stay accepted at level 1.
func TestNewServerRefusesShowResultsOnDesktop(t *testing.T) {
	for _, level := range []int{1, 2} {
		log, _ := audit.Open(testProduct, t.TempDir())
		_, err := NewServer(ServerConfig{Product: testProduct, Backend: &fakeBackend{policy: uat()}, Policy: uat(),
			Session: &fakeSession{}, Audit: log, IO: &fakeIO{}, Level: level, ShowResults: true})
		if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "--show-results") {
			t.Errorf("level %d: err = %v", level, err)
		}
	}
	h := newHarness(t, uat(), func(c *ServerConfig) { c.ShowResults = true })
	if !h.s.ShowResults() {
		t.Error("level 0 lost ShowResults")
	}
	h1 := newHarness(t, uat(), func(c *ServerConfig) { c.Level, c.Auto, c.AllowUnmask = 1, true, true })
	if !h1.s.Auto() || !h1.s.UnmaskAllowed() {
		t.Error("level 1 refused --auto or --allow-unmask")
	}
}

// Run refuses --show-results at level 1 before any prompt, session or
// audit record; level 2 keeps its own refusal.
func TestRunRefusesShowResultsAtLevel1(t *testing.T) {
	env := desktopEnvFake()
	env.NewVerifier = func(string) (fingerprint.Verifier, error) {
		return &fingerprint.Fake{EnrolledErr: fingerprint.ErrNotEnrolled}, nil
	}
	b := &fakeBackend{policy: uat()}
	io := &fakeIO{answers: []string{"y"}}
	state := t.TempDir()
	err := Run(context.Background(), testProduct, b, Options{Profile: "uat", IO: io, StateDir: state, Isolation: &env,
		ShowResults: true, Harden: func() error { return nil }})
	if !errors.Is(err, ErrConfig) || err.Error() != "configuration error: level 1 does not accept --show-results: the agent's account can read this window" {
		t.Fatalf("err = %v", err)
	}
	if io.promptCount() != 0 || len(b.sessions) != 0 {
		t.Fatalf("prompts %d sessions %d", io.promptCount(), len(b.sessions))
	}
	if entries, _ := os.ReadDir(state); len(entries) != 0 {
		t.Fatalf("state written: %v", entries)
	}
	env2 := desktopEnvFake()
	err = Run(context.Background(), testProduct, b, Options{Profile: "uat", IO: &fakeIO{}, StateDir: t.TempDir(), Isolation: &env2,
		ShowResults: true, Harden: func() error { return nil }})
	if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "level 2 does not accept") {
		t.Fatalf("level 2: %v", err)
	}
}

func TestChangeRequestQueuedForReview(t *testing.T) {
	h := newHarness(t, uat(), nil)
	r := h.call(t, context.Background(), ipc.MethodChangeRequest, ipc.ChangeParams{Change: "tier = peek \x1b[31m"})
	var cr ipc.ChangeResult
	if r.Error != nil || json.Unmarshal(r.Result, &cr) != nil || !cr.Queued {
		t.Fatalf("%+v", r)
	}
	if r := h.call(t, context.Background(), ipc.MethodChangeRequest, ipc.ChangeParams{Change: ""}); r.Error == nil {
		t.Fatal("empty change accepted")
	}
	if !strings.Contains(h.io.statusLine(), "1 change request") {
		t.Fatalf("status %q", h.io.statusLine())
	}
	h.s.Command(context.Background(), ":review")
	if !strings.Contains(h.io.plain(), `tier = peek \x1b[31m`) || h.s.Policy().(fakePolicy).Tier != "read" {
		t.Fatalf("review: %s", h.io.plain())
	}
}

// The AI tightens, the human loosens.
func TestCheckPolicyTightensAtOnceLoosenWaitsForReview(t *testing.T) {
	h := newHarness(t, uat(), nil)
	tighter := uat()
	tighter.MaxRows = 10
	h.b.policy = tighter
	h.s.CheckPolicy()
	if h.s.Policy().(fakePolicy).MaxRows != 10 || h.s.PolicyPending() {
		t.Fatal("tightening not applied at once")
	}
	if ok, _ := config.LoadApproved(testProduct, h.state, "user-uat", &fakePolicy{}); !ok {
		t.Fatal("tightening not saved")
	}
	if rec := h.lastRecord(t); rec["event"] != "policy" || rec["decision"] != "tightened" {
		t.Fatalf("audit: %v", rec)
	}

	looser := tighter
	looser.Tier = "peek"
	h.b.policy = looser
	h.s.CheckPolicy()
	if h.s.Policy().(fakePolicy).Tier != "read" || !h.s.PolicyPending() || !strings.Contains(h.io.statusLine(), "policy change pending") {
		t.Fatal("loosening applied without the human")
	}
	// Refused: kept out until the files change.
	h.io.answers = []string{"n"}
	h.s.Command(context.Background(), ":review")
	if h.s.Policy().(fakePolicy).Tier != "read" || h.s.PolicyPending() {
		t.Fatal("refused loosening applied")
	}
	h.s.CheckPolicy()
	if h.s.PolicyPending() {
		t.Fatal("a refused loosening announced again")
	}
	// Changed again: announced, and applied on a yes.
	looser.MaxRows = 30
	h.b.policy = looser
	h.s.CheckPolicy()
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	if p := h.s.Policy().(fakePolicy); p.Tier != "peek" || p.MaxRows != 30 {
		t.Fatalf("approved loosening not applied: %+v", p)
	}
	if rec := h.lastRecord(t); rec["event"] != "policy" || rec["decision"] != "applied" || rec["approval"] != "session" {
		t.Fatalf("audit: %v", rec)
	}
	// A config error is said once.
	h.b.loadErr = errors.New("bad toml")
	h.s.CheckPolicy()
	h.s.CheckPolicy()
	if n := strings.Count(h.io.plain(), "config error: bad toml"); n != 1 {
		t.Fatalf("config error said %d times", n)
	}
}

// Moving the backend ends the session: the connection no longer matches.
func TestAdoptedHostChangeEndsSession(t *testing.T) {
	h := newHarness(t, uat(), nil)
	moved := uat()
	moved.Host = "other.example.com"
	h.b.policy = moved
	h.s.CheckPolicy()
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	if reason, ended := h.s.Ended(); !ended || reason != "connection settings changed" {
		t.Fatalf("ended %v %q", ended, reason)
	}
	if strings.Contains(h.io.plain(), "policy change applied") {
		t.Fatalf("applied said of a session that ends:\n%s", h.io.plain())
	}
}

// A profile turned production refuses findings it accepted at start.
func TestBecomingProductionRunsChecks(t *testing.T) {
	h := newHarness(t, uat(), nil)
	h.b.findings = []Finding{{Text: "can publish"}}
	p := uat()
	p.Production = true
	h.b.policy = p
	h.s.CheckPolicy() // tightening: applied at once
	if reason, ended := h.s.Ended(); !ended || !strings.Contains(reason, "checks failed") {
		t.Fatalf("ended %v %q", ended, reason)
	}
}

// A profile turned production re-applies the start-up refusals before
// the checks: the session ends.
func TestBecomingProductionReappliesStartRefusals(t *testing.T) {
	iso := &Isolation{Display: sysconf.Display{Kind: sysconf.DisplayX11}}
	h := newHarness(t, uat(), func(c *ServerConfig) {
		c.RefuseProduction = func() error { return iso.RefuseX11IfProduction(true) }
	})
	p := uat()
	p.Production = true
	h.b.policy = p
	h.s.CheckPolicy()
	if reason, ended := h.s.Ended(); !ended || reason != "refused after the profile became production" {
		t.Fatalf("ended %v %q", ended, reason)
	}
	if !strings.Contains(h.io.plain(), "X11 session") {
		t.Fatalf("no refusal shown:\n%s", h.io.plain())
	}
}

func TestTickTimeouts(t *testing.T) {
	now := time.Now()
	clock := now
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Now = func() time.Time { return clock } })
	clock = now.Add(19 * time.Minute)
	h.s.Tick()
	if _, ended := h.s.Ended(); ended {
		t.Fatal("ended before the idle timeout")
	}
	clock = now.Add(21 * time.Minute)
	h.s.Tick()
	if reason, ended := h.s.Ended(); !ended || reason != "idle timeout" {
		t.Fatalf("idle: %v %q", ended, reason)
	}
}

func TestSessionTTLReconnects(t *testing.T) {
	now := time.Now()
	clock := now
	p := uat()
	p.Base.CredentialsTTL = time.Minute
	reconnects := 0
	h := newHarness(t, p, func(c *ServerConfig) {
		c.Now = func() time.Time { return clock }
		c.Reconnect = func(context.Context, Profile) (Session, error) { reconnects++; return &fakeSession{}, nil }
	})
	first, _ := h.s.Session(context.Background())
	clock = now.Add(2 * time.Minute)
	second, err := h.s.Session(context.Background())
	if err != nil || reconnects != 1 || first == second || !first.(*fakeSession).closed {
		t.Fatalf("ttl: reconnects %d err %v", reconnects, err)
	}
	h.s.Lost()
	if _, err := h.s.Session(context.Background()); err != nil || reconnects != 2 {
		t.Fatalf("lost: %d %v", reconnects, err)
	}
	h2 := newHarness(t, uat(), nil)
	h2.s.Lost()
	if _, err := h2.s.Session(context.Background()); err == nil {
		t.Fatal("no reconnect, yet a session")
	}
	if _, ended := h2.s.Ended(); !ended {
		t.Fatal("a lost connection without reconnect does not end the console")
	}
}

// runEnv is a same-user test console (AllowSameUser) on a private socket.
func runEnv(t *testing.T) *IsolationEnv {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "lkrun")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	t.Setenv("LOCKMQ_RUNTIME_DIR", d)
	env := fakeIsolation(nil, sysconf.DisplayWayland)
	env.AllowSameUser = true
	return &env
}

func dialAndCall(t *testing.T, socket, method string, params any) ipc.Response {
	t.Helper()
	var resp ipc.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("unix", socket)
		if err == nil {
			defer c.Close()
			raw, _ := json.Marshal(params)
			if err := ipc.WriteMsg(c, ipc.Request{JSONRPC: "2.0", ID: 1, Method: method, Params: raw}); err != nil {
				t.Fatal(err)
			}
			if err := ipc.ReadMsg(bufio.NewReader(c), &resp); err != nil {
				t.Fatal(err)
			}
			return resp
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Run end to end: first-start review, the user and the secret asked, the
// checks accepted with "continue", the socket served, logout audited.
func TestRunEndToEnd(t *testing.T) {
	env := runEnv(t)
	b := &fakeBackend{policy: uat(), findings: []Finding{{Text: "the account can configure queues"}}}
	b.policy.Base.User = ""
	io := &fakeIO{answers: []string{"y", "alice", "continue", "y"}, secrets: []string{"s3cret"}}
	state := t.TempDir()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), testProduct, b, Options{Profile: "uat", IO: io, StateDir: state, Isolation: env,
			Harden: func() error { return nil }, Quantum: -1, Ready: func(s string) { ready <- s }})
	}()
	var socket string
	select {
	case socket = <-ready:
	case err := <-done:
		t.Fatalf("Run: %v\n%s", err, io.plain())
	case <-time.After(10 * time.Second):
		t.Fatal("no socket")
	}
	if r := dialAndCall(t, socket, "op.read", map[string]string{"queue": "orders"}); r.Error != nil {
		t.Fatalf("op.read: %+v\n%s", r.Error, io.plain())
	}
	if r := dialAndCall(t, socket, ipc.MethodLogout, nil); r.Error != nil {
		t.Fatal(r.Error)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(b.creds) != 1 || b.creds[0].User != "alice" || string(b.creds[0].Secret) != "s3cret" {
		t.Fatalf("credentials %+v", b.creds)
	}
	if ok, _ := config.LoadApproved(testProduct, state, "user-uat", &fakePolicy{}); !ok {
		t.Fatal("first-start policy not saved")
	}
	raw, _ := os.ReadFile(filepath.Join(state, "lockmq", "audit.log"))
	var events []string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var m map[string]any
		_ = json.Unmarshal([]byte(l), &m)
		events = append(events, fmt.Sprint(m["event"]))
	}
	if strings.Join(events, ",") != "policy,login,approved,logout" {
		t.Fatalf("events %v", events)
	}
	if strings.Contains(string(raw), "s3cret") {
		t.Fatal("secret in the audit log")
	}
}

// Production: a finding refuses; the profile name is typed to start.
func TestRunProductionRefusesFindings(t *testing.T) {
	env := runEnv(t)
	b := &fakeBackend{policy: prod(), findings: []Finding{{Text: "the account can publish"}}}
	io := &fakeIO{answers: []string{"y", "prod"}, secrets: []string{"pw"}}
	err := Run(context.Background(), testProduct, b, Options{Profile: "prod", IO: io, StateDir: t.TempDir(), Isolation: env, Harden: func() error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "refused by the checks") || len(b.sessions) != 1 || !b.sessions[0].closed {
		t.Fatalf("err = %v sessions %d", err, len(b.sessions))
	}
	b2 := &fakeBackend{policy: prod()}
	io2 := &fakeIO{answers: []string{"y", "PROD"}, secrets: []string{"pw"}}
	if err := Run(context.Background(), testProduct, b2, Options{Profile: "prod", IO: io2, StateDir: t.TempDir(), Isolation: env, Harden: func() error { return nil }}); err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("unconfirmed production: %v", err)
	}
	if err := Run(context.Background(), testProduct, &fakeBackend{policy: prod()}, Options{Profile: "prod", IO: &fakeIO{answers: []string{"y"}}, StateDir: t.TempDir(), Isolation: env,
		Harden: func() error { return errors.New("no rlimit") }}); err == nil || !strings.Contains(err.Error(), "core dumps could not be disabled") {
		t.Fatalf("production without hardening: %v", err)
	}
}

// A console started on a non-production profile ends when the profile
// becomes production in an X11 session or without core-dump hardening.
func TestRunBecomingProductionReappliesStartRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		display string
		harden  error
		want    string
	}{
		{"x11", sysconf.DisplayX11, nil, "X11 session"},
		{"core dumps", sysconf.DisplayWayland, errors.New("no rlimit"), "core dumps could not be disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := runEnv(t)
			env.Display = func() sysconf.Display { return sysconf.Display{Kind: tc.display} }
			b := &fakeBackend{policy: uat()}
			io := &fakeIO{answers: []string{"y"}, secrets: []string{"pw"}}
			ready := make(chan string, 1)
			done := make(chan error, 1)
			go func() {
				done <- Run(context.Background(), testProduct, b, Options{Profile: "uat", IO: io, StateDir: t.TempDir(), Isolation: env,
					Harden: func() error { return tc.harden }, Quantum: -1, Ready: func(s string) { ready <- s }})
			}()
			select {
			case <-ready:
			case err := <-done:
				t.Fatalf("Run: %v\n%s", err, io.plain())
			case <-time.After(10 * time.Second):
				t.Fatal("no socket")
			}
			p := uat()
			p.Production = true
			b.mu.Lock()
			b.policy = p
			b.mu.Unlock()
			select {
			case <-done:
			case <-time.After(3*PolicyPoll + 5*time.Second):
				t.Fatal("the console kept serving a production profile")
			}
			out := io.plain()
			if !strings.Contains(out, "session ended: refused after the profile became production") || !strings.Contains(out, tc.want) {
				t.Fatalf("output:\n%s", out)
			}
		})
	}
}

// A loosening since the approved policy is reviewed at start; refused, the
// approved policy applies and is not announced again.
func TestRunLoosenedPolicyReviewedAtStart(t *testing.T) {
	env := runEnv(t)
	state := t.TempDir()
	if err := config.SaveApproved(testProduct, state, "user-uat", uat()); err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{policy: uat()}
	b.policy.Tier = "peek"
	io := &fakeIO{answers: []string{"n"}, secrets: []string{"pw"}}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), testProduct, b, Options{Profile: "uat", IO: io, StateDir: state, Isolation: env,
			Harden: func() error { return nil }, Ready: func(s string) { ready <- s }})
	}()
	var socket string
	select {
	case socket = <-ready:
	case err := <-done:
		t.Fatalf("Run: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no socket")
	}
	dialAndCall(t, socket, ipc.MethodLogout, nil)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(io.plain(), "changes refused: the last approved policy applies") || !strings.Contains(io.plain(), "tier: read → peek  (loosens)") {
		t.Fatalf("review:\n%s", io.plain())
	}
	var ap fakePolicy
	if ok, _ := config.LoadApproved(testProduct, state, "user-uat", &ap); !ok || ap.Tier != "read" {
		t.Fatalf("approved policy changed: %+v", ap)
	}
}

// Keychain credentials: read, used, and offered for saving when asked.
func TestRunKeychainAndVault(t *testing.T) {
	env := runEnv(t)
	kc := secrets.NewKeychain("lockmq-test")
	p := uat()
	p.Base.Credentials = config.CredentialsVault
	p.Base.VaultPath = "rabbitmq/creds/ro"
	p.Base.User = ""
	b := &fakeBackend{policy: p}
	io := &fakeIO{answers: []string{"y"}}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), testProduct, b, Options{Profile: "uat", IO: io, StateDir: t.TempDir(), Isolation: env,
			Harden: func() error { return nil }, Keychain: &kc, Ready: func(s string) { ready <- s },
			VaultRead: func(context.Context, string) (*secrets.VaultCredentials, error) {
				return &secrets.VaultCredentials{User: "vault-user", Password: []byte("vpw")}, nil
			}})
	}()
	socket := <-ready
	dialAndCall(t, socket, ipc.MethodLogout, nil)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(b.creds) != 1 || b.creds[0].User != "vault-user" || string(b.creds[0].Secret) != "vpw" {
		t.Fatalf("vault creds %+v", b.creds)
	}
	if !strings.Contains(io.plain(), "credentials from Vault: rabbitmq/creds/ro · user vault-user") {
		t.Fatalf("out:\n%s", io.plain())
	}
}

func readOnlyAudit(t *testing.T, path string) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("root writes a read-only file")
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
}

// A widening takes effect only once recorded: auto mode, clear results,
// unmask and a loosened policy stay off when the audit write fails.
func TestWideningAuditFailureKeepsSwitchesOff(t *testing.T) {
	h := newHarness(t, uat(), nil)
	readOnlyAudit(t, h.log)
	h.s.toggleMode()
	if h.s.auto {
		t.Error("auto mode on without a record")
	}
	h.s.toggleResults()
	if h.s.showResults {
		t.Error("clear results shown without a record")
	}
	h.io.answers = []string{"y"}
	h.s.toggleUnmask(context.Background())
	if h.s.allowUnmask {
		t.Error("unmask allowed without a record")
	}
	if !strings.Contains(h.io.plain(), "not recorded in the audit log, so it stays off") {
		t.Fatalf("the human was not told:\n%s", h.io.plain())
	}
}

func TestAdoptAppliedAuditFailure(t *testing.T) {
	h := newHarness(t, uat(), nil)
	readOnlyAudit(t, h.log)
	next := uat()
	next.MaxRows = 1000
	if err := h.s.adopt(next, "applied"); err == nil {
		t.Fatal("loosening adopted without a record")
	}
	if h.s.approved.(fakePolicy).MaxRows == 1000 {
		t.Error("loosening applied without a record")
	}
	var got fakePolicy
	if ok, _ := config.LoadApproved(testProduct, h.state, "user-uat", &got); ok {
		t.Error("loosening saved without a record")
	}
}

func TestStartPolicyAuditFailure(t *testing.T) {
	state := t.TempDir()
	log, err := audit.Open(testProduct, state)
	if err != nil {
		t.Fatal(err)
	}
	readOnlyAudit(t, log.Path())
	io := &fakeIO{answers: []string{"y"}}
	st := &starter{p: testProduct, b: &fakeBackend{policy: uat()}, io: io, log: log, profile: uat().Profile(), approver: NewTypedApprover(io)}
	if _, _, err := st.startPolicy(context.Background(), state, "user-uat", uat()); err == nil {
		t.Fatal("first-start policy approved without a record")
	}
	var got fakePolicy
	if ok, _ := config.LoadApproved(testProduct, state, "user-uat", &got); ok {
		t.Error("policy saved without a record")
	}
}

// An approval on record whose save fails gets a "failed" record: the log
// never claims a change that did not happen.
func TestAdoptAppliedSaveFailureRecorded(t *testing.T) {
	h := newHarness(t, uat(), nil)
	dir := filepath.Join(h.state, testProduct.Name, "approved")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	next := uat()
	next.MaxRows = 1000
	if err := h.s.adopt(next, "applied"); err == nil {
		t.Fatal("adopted although the save failed")
	}
	recs := h.records(t)
	if len(recs) < 2 || recs[len(recs)-2]["decision"] != "applied" || recs[len(recs)-1]["decision"] != "failed" || recs[len(recs)-1]["error"] == "" {
		t.Fatalf("records %v", recs)
	}
}
