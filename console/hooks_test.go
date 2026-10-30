//go:build unix

package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/secrets"
)

// hookBackend implements every product hook.
type hookBackend struct {
	*fakeBackend
	applied  []fakePolicy
	applyErr error
	// failAfter applies that many policies, then refuses the next ones.
	failAfter int
	failNext  bool
	checked   []Session
}

func (b *hookBackend) StatusAnswer(c StatusResult, s Session) any {
	return map[string]any{"profile": c.Profile, "auto_approve": c.AutoApprove, "tier": b.policy.Tier, "connected": s != nil}
}

func (b *hookBackend) StatusRows(v StatusView) [][2]string {
	return [][2]string{{"profile", v.Profile.Name + " · tier " + v.Policy.(fakePolicy).Tier},
		{"mode", StatusModeRow(v, b.Words())}, {"results", StatusResultsRow(v, b.Words())},
		{"unmask", StatusUnmaskRow(v)}, {"policy change", StatusPendingRow(v)}, {"queued", fmt.Sprint(v.Requests)}}
}

func (b *hookBackend) StatusLineParts(v StatusView) (string, []string) {
	return "tier " + v.Policy.(fakePolicy).Tier, []string{"2 plans open"}
}

func (b *hookBackend) FormatChanges(changes []config.Change) []string {
	var out []string
	for _, c := range changes {
		out = append(out, "  * "+c.Field)
	}
	return out
}

func (b *hookBackend) ConnectionChanged(old, next Policy) bool {
	return old.(fakePolicy).MaxRows == 99 || next.(fakePolicy).MaxRows == 99
}

func (b *hookBackend) ApplyPolicy(p Policy) error {
	if b.applyErr != nil {
		return b.applyErr
	}
	if b.failAfter > 0 {
		b.failAfter--
		if b.failAfter == 0 {
			b.failNext = true
		}
	} else if b.failNext {
		return errors.New("rollback refused")
	}
	b.applied = append(b.applied, p.(fakePolicy))
	return nil
}

func (b *hookBackend) Words() Words {
	return Words{
		AutoStart: "auto mode: statements run (start)", AutoOn: "auto mode: statements run", Manual: "manual mode: every statement",
		NoAutoProduction: "no auto on production statements", NoAutoHub: "no auto in hub mode",
		StatusAuto: "auto: statements", StatusManual: "manual: statements", ResultsOn: "results: PII in clear", StatusResults: "PII in clear",
		UnmaskAsk: "unmask PII?", UnmaskOff: "unmask: off, plans refused", ReviewAuto: "auto mode is on: statements run",
		ChangeQueued: func(c string) string { return "queued: " + c },
		Reconnecting: "reconnecting to the database…",
		TTLReached:   func(ttl time.Duration, cred string) string { return fmt.Sprintf("ttl %s %s", ttl, cred) },
		ProductionChecks: func(p Profile, f []Finding) (string, string) {
			return "privileges beyond " + p.Name, "privilege audit failed"
		},
		ConnLost: "the database connection is lost",
	}
}

func (b *hookBackend) Checks(_ context.Context, s Session) []Finding {
	b.checked = append(b.checked, s)
	return b.findings
}

func newHookHarness(t *testing.T, p fakePolicy, mutate func(*ServerConfig)) (*harness, *hookBackend) {
	t.Helper()
	hb := &hookBackend{fakeBackend: &fakeBackend{policy: p}}
	h := newHarness(t, p, func(c *ServerConfig) {
		c.Backend = hb
		if mutate != nil {
			mutate(c)
		}
	})
	h.b = hb.fakeBackend
	return h, hb
}

// A backend without hooks keeps the console's own text: the other tests
// and the goldens. With them, the product's.
func TestHooksStatus(t *testing.T) {
	h, _ := newHookHarness(t, uat(), func(c *ServerConfig) { c.Auto = true })
	if !strings.Contains(h.io.plain(), "auto mode: statements run (start)") {
		t.Fatalf("start:\n%s", h.io.plain())
	}
	r := h.call(t, context.Background(), ipc.MethodStatus, nil)
	if r.Error != nil || string(r.Result) != `{"auto_approve":true,"connected":true,"profile":"uat","tier":"read"}` {
		t.Fatalf("flat status: %s %+v", r.Result, r.Error)
	}
	h.s.Lost()
	r = h.call(t, context.Background(), ipc.MethodStatus, nil)
	if !strings.Contains(string(r.Result), `"connected":false`) {
		t.Fatalf("disconnected status: %s", r.Result)
	}
	h.call(t, context.Background(), ipc.MethodChangeRequest, ipc.ChangeParams{Change: "tier = peek"})
	if !strings.Contains(h.io.plain(), "queued: tier = peek") {
		t.Fatalf("change request:\n%s", h.io.plain())
	}
	h.s.Command(context.Background(), ":status")
	out := h.io.plain()
	for _, want := range []string{"  profile        uat · tier read", "  mode           auto: statements (Shift+Tab or :mode)",
		"  results        masked (the agent's view) (Ctrl-O or :results)", "  queued         1"} {
		if !strings.Contains(out, want) {
			t.Errorf(":status lacks %q:\n%s", want, out)
		}
	}
	if st := h.io.statusLine(); !strings.HasPrefix(st, "UAT tier read · mode AUTO") || !strings.Contains(st, "results masked ^O · 2 plans open · 1 change request") {
		t.Fatalf("status row %q", st)
	}
}

func TestHooksModesWording(t *testing.T) {
	h, _ := newHookHarness(t, uat(), nil)
	h.s.Key(KeyShiftTab)
	h.s.Key(KeyShiftTab)
	h.s.Key(KeyCtrlO)
	h.io.answers = []string{"n"}
	h.s.Command(context.Background(), ":unmask")
	h.s.allowUnmask = true
	h.s.Command(context.Background(), ":unmask")
	out := h.io.plain()
	for _, want := range []string{"auto mode: statements run", "manual mode: every statement", "results: PII in clear", "unmask PII?", "unmask: off, plans refused"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	p, _ := newHookHarness(t, prod(), nil)
	p.s.Key(KeyShiftTab)
	if !strings.Contains(p.io.plain(), "no auto on production statements") {
		t.Fatalf("production:\n%s", p.io.plain())
	}
	hub, _ := newHookHarness(t, uat(), func(c *ServerConfig) { c.Hub = &Hub{} })
	hub.s.Key(KeyShiftTab)
	if hub.s.auto || !strings.Contains(hub.io.plain(), "no auto in hub mode") {
		t.Fatalf("hub: auto %v\n%s", hub.s.auto, hub.io.plain())
	}
	// Without NoAutoHub the console keeps its behaviour: the switch moves.
	plain := newHarness(t, uat(), func(c *ServerConfig) { c.Hub = &Hub{} })
	plain.s.Key(KeyShiftTab)
	if !plain.s.auto {
		t.Fatal("hub mode without NoAutoHub refused the switch")
	}
}

func TestHooksPolicy(t *testing.T) {
	h, hb := newHookHarness(t, uat(), func(c *ServerConfig) { c.Auto = true })
	if len(hb.applied) != 1 || hb.applied[0].Name != "uat" {
		t.Fatalf("start policy not applied: %+v", hb.applied)
	}
	// A tightening: formatted by the backend, applied to it.
	tighter := uat()
	tighter.MaxRows = 10
	h.b.policy = tighter
	h.s.CheckPolicy()
	if !strings.Contains(h.io.plain(), "policy tightened:\n  * limits.max_rows") || len(hb.applied) != 2 {
		t.Fatalf("tightened:\n%s\n%+v", h.io.plain(), hb.applied)
	}
	// :review: the backend's diff and wording.
	looser := tighter
	looser.Tier = "peek"
	h.b.policy = looser
	h.s.CheckPolicy()
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	if !strings.Contains(h.io.plain(), "pending policy change for profile uat:\n  * tier") {
		t.Fatalf("review:\n%s", h.io.plain())
	}
	// The backend's connection check ends the session.
	moved := looser
	moved.MaxRows = 99
	h.b.policy = moved
	h.s.CheckPolicy()
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	if reason, ended := h.s.Ended(); !ended || reason != "connection settings changed" {
		t.Fatalf("ended %v %q", ended, reason)
	}
	// NewServer refuses a start policy the backend refuses.
	log, _ := audit.Open(testProduct, t.TempDir())
	bad := &hookBackend{fakeBackend: &fakeBackend{policy: uat()}, applyErr: errors.New("no dialect")}
	if _, err := NewServer(ServerConfig{Product: testProduct, Backend: bad, Policy: uat(), Audit: log, IO: &fakeIO{}}); err == nil || err.Error() != "no dialect" {
		t.Fatalf("NewServer: %v", err)
	}
}

func TestHooksReviewAutoAndProduction(t *testing.T) {
	h, hb := newHookHarness(t, prod(), func(c *ServerConfig) { c.Auto = true })
	off := prod()
	off.Production = false
	h.b.policy = off
	h.s.CheckPolicy()
	h.io.answers = []string{"n"}
	h.s.Command(context.Background(), ":review")
	if !strings.Contains(h.io.plain(), "auto mode is on: statements run") {
		t.Fatalf("review:\n%s", h.io.plain())
	}
	// Becoming production with findings: the product's words.
	u, hb2 := newHookHarness(t, uat(), nil)
	hb2.findings = []Finding{{Text: "can write"}}
	p := uat()
	p.Production = true
	u.b.policy = p
	u.s.CheckPolicy()
	if reason, ended := u.s.Ended(); !ended || reason != "privilege audit failed" || !strings.Contains(u.io.plain(), "privileges beyond uat") {
		t.Fatalf("ended %v %q\n%s", ended, reason, u.io.plain())
	}
	_ = hb
}

func TestHooksSession(t *testing.T) {
	now := time.Now()
	clock := now
	p := uat()
	p.Base.CredentialsTTL = time.Minute
	var got []Policy
	var next error
	h, _ := newHookHarness(t, p, func(c *ServerConfig) {
		c.Now = func() time.Time { return clock }
		c.Reconnect = func(context.Context, Profile) (Session, error) {
			t.Fatal("Reconnect used with ReconnectPolicy")
			return nil, nil
		}
		c.ReconnectPolicy = func(_ context.Context, p Policy) (Session, error) {
			got = append(got, p)
			if next != nil {
				return nil, next
			}
			return &fakeSession{}, nil
		}
	})
	clock = now.Add(2 * time.Minute)
	if _, err := h.s.Session(context.Background()); err != nil || len(got) != 1 || got[0].(fakePolicy).Name != "uat" {
		t.Fatalf("reconnect: %v %+v", err, got)
	}
	if out := h.io.plain(); !strings.Contains(out, "ttl 1m0s ask") || !strings.Contains(out, "reconnecting to the database…") {
		t.Fatalf("out:\n%s", out)
	}
	// An EndError ends the session with its reason; the handler gets the
	// product's text.
	next = &EndError{Reason: "privilege audit failed after reconnect", Err: errors.New("extra grants")}
	h.s.Lost()
	_, err := h.s.Session(context.Background())
	if reason, ended := h.s.Ended(); err == nil || err.Error() != "the database connection is lost" || !ended || reason != "privilege audit failed after reconnect" {
		t.Fatalf("end error: %v %v %q", err, ended, reason)
	}
	// A plain failure does not end it.
	h2, _ := newHookHarness(t, uat(), func(c *ServerConfig) {
		c.ReconnectPolicy = func(context.Context, Policy) (Session, error) { return nil, errors.New("refused") }
	})
	h2.s.Lost()
	if _, err := h2.s.Session(context.Background()); err == nil {
		t.Fatal("a session after a failed reconnect")
	}
	if _, ended := h2.s.Ended(); ended {
		t.Fatal("a failed reconnect ended the session")
	}
}

// AskerOf and PolicyPendingOf reach the console behind an Env.
func TestAskerOfAndPolicyPendingOf(t *testing.T) {
	h := newHarness(t, uat(), nil)
	a, ok := AskerOf(h.s)
	if !ok || a.Profile != "uat" || a.Lock != testProduct.Name {
		t.Fatalf("asker %+v %v", a, ok)
	}
	// A decision through it counts as a prompt: a widening waits.
	h.io.answers = []string{"y"}
	a.Approver = &keyApprover{Approver: a.Approver, during: func() { h.s.Key(KeyShiftTab) }}
	if r := a.Decide(context.Background(), Decision{Prompt: "Approve? ", Expected: "y"}); r.Outcome != Approved {
		t.Fatalf("decide %+v", r)
	}
	if h.s.auto || !strings.Contains(h.io.plain(), "auto mode: not while a prompt waits") {
		t.Fatalf("auto %v\n%s", h.s.auto, h.io.plain())
	}
	if PolicyPendingOf(h.s) {
		t.Fatal("pending without a loosening")
	}
	looser := uat()
	looser.Tier = "peek"
	h.b.policy = looser
	h.s.CheckPolicy()
	if !PolicyPendingOf(h.s) {
		t.Fatal("pending loosening not reported")
	}
	h.io.answers = []string{"n"}
	h.s.Command(context.Background(), ":review")
	if PolicyPendingOf(h.s) || !h.s.PolicyRefused() {
		t.Fatal("refused loosening not reported")
	}
	h.b.policy = uat()
	h.s.CheckPolicy()
	if h.s.PolicyRefused() {
		t.Fatal("a reverted loosening still reported refused")
	}
	if _, ok := AskerOf(nil); ok {
		t.Fatal("an asker from no console")
	}
}

func TestUnwrap(t *testing.T) {
	fs := &fakeSession{}
	if Unwrap(fs) != Session(fs) {
		t.Fatal("unwrapped a plain session")
	}
	if Unwrap(&expiringSession{Session: fs}) != Session(fs) {
		t.Fatal("expiring session not unwrapped")
	}
	if Unwrap(nil) != nil {
		t.Fatal("nil")
	}
}

// Run passes the approved policy to Connect, and a Vault-leased session
// unwraps to the backend's own.
func TestRunConnectGetsPolicyAndUnwraps(t *testing.T) {
	env := runEnv(t)
	kc := secrets.NewKeychain("lockmq-test")
	p := uat()
	p.Base.Credentials = config.CredentialsVault
	p.Base.VaultPath = "rabbitmq/creds/ro"
	p.Base.User = ""
	hb := &hookBackend{fakeBackend: &fakeBackend{policy: p}}
	io := &fakeIO{answers: []string{"y"}}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), testProduct, hb, Options{Profile: "uat", IO: io, StateDir: t.TempDir(), Isolation: env,
			Harden: func() error { return nil }, Keychain: &kc, Ready: func(s string) { ready <- s },
			VaultRead: func(context.Context, string) (*secrets.VaultCredentials, error) {
				return &secrets.VaultCredentials{User: "vault-user", Password: []byte("vpw"), LeaseID: "l1", LeaseDuration: time.Hour}, nil
			}})
	}()
	socket := <-ready
	r := dialAndCall(t, socket, ipc.MethodStatus, nil)
	var st map[string]any
	if json.Unmarshal(r.Result, &st) != nil || st["connected"] != true {
		t.Fatalf("status %s", r.Result)
	}
	dialAndCall(t, socket, ipc.MethodLogout, nil)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(hb.creds) != 1 || hb.creds[0].Policy == nil || hb.creds[0].Policy.(fakePolicy).Name != "uat" {
		t.Fatalf("creds %+v", hb.creds)
	}
	if len(hb.checked) != 1 {
		t.Fatalf("checks %d", len(hb.checked))
	}
	if _, wrapped := hb.checked[0].(*expiringSession); !wrapped {
		t.Fatalf("the leased session is not wrapped: %T", hb.checked[0])
	}
	if _, ok := Unwrap(hb.checked[0]).(*fakeSession); !ok {
		t.Fatalf("Unwrap: %T", Unwrap(hb.checked[0]))
	}
}

// WriteAudit returns the failure and counts it.
func TestWriteAudit(t *testing.T) {
	h := newHarness(t, uat(), nil)
	if err := h.s.WriteAudit(audit.Base{Event: audit.EventRun, Decision: "ok"}); err != nil {
		t.Fatal(err)
	}
	for range maxAuditFails {
		if err := h.s.WriteAudit(nil); err == nil {
			t.Fatal("a nil record written")
		}
	}
	if reason, ended := h.s.Ended(); !ended || reason != "the audit log cannot be written" {
		t.Fatalf("ended %v %q", ended, reason)
	}
}

// A tightening the backend cannot apply is neither saved nor applied, is
// audited, and ends the session: serving on under the looser policy would
// fail open. A refused loosening (at :review) only stays out.
func TestHooksRefusedPolicy(t *testing.T) {
	h, hb := newHookHarness(t, uat(), nil)
	hb.applyErr = errors.New("bad rules")
	worse := uat()
	worse.MaxRows = 5
	h.b.policy = worse
	h.s.CheckPolicy()
	if h.s.Policy().(fakePolicy).MaxRows != 20 {
		t.Fatal("refused tightening in force")
	}
	if reason, ended := h.s.Ended(); !ended || reason != "a tightened policy could not be applied" {
		t.Fatalf("ended %v %q", ended, reason)
	}
	if rec := h.lastRecord(t); rec["event"] != "policy" || rec["decision"] != "failed" || !strings.Contains(rec["error"].(string), "bad rules") {
		t.Fatalf("audit %v", rec)
	}
	if ok, _ := config.LoadApproved(testProduct, h.state, "user-uat", &fakePolicy{}); ok {
		t.Fatal("refused tightening saved")
	}
	// pii.add goes the same way: the rule is in the file, so the session
	// cannot serve without it.
	pb := &piiApplyBackend{piiBackend: &piiBackend{pol: piiUAT()}}
	p := newHarness(t, uat(), func(c *ServerConfig) { c.Backend, c.Policy = pb, piiUAT() })
	pb.err = errors.New("bad rules")
	if r := p.call(t, context.Background(), ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "orders.phone"}); r.Error == nil {
		t.Fatal("pii.add answered ok")
	}
	if reason, ended := p.s.Ended(); !ended || reason != "a tightened policy could not be applied" {
		t.Fatalf("pii.add: ended %v %q", ended, reason)
	}
	// A loosening refused by the backend at :review stays out; the session goes on.
	l, lb := newHookHarness(t, uat(), nil)
	looser := uat()
	looser.Tier = "peek"
	l.b.policy = looser
	l.s.CheckPolicy()
	lb.applyErr = errors.New("bad rules")
	l.io.answers = []string{"y"}
	l.s.Command(context.Background(), ":review")
	if l.s.Policy().(fakePolicy).Tier != "read" || !strings.Contains(l.io.plain(), "policy change not applied: bad rules") {
		t.Fatalf("loosening:\n%s", l.io.plain())
	}
	if _, ended := l.s.Ended(); ended {
		t.Fatal("a refused loosening ended the session")
	}
	if rec := l.lastRecord(t); rec["decision"] != "failed" {
		t.Fatalf("audit %v", rec)
	}
}

// A failed save applies the policy in force back to the backend; when that
// fails too, the session ends.
func TestHooksSaveFailureRollback(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	for _, rollbackFails := range []bool{false, true} {
		h, hb := newHookHarness(t, uat(), nil)
		dir := filepath.Join(h.state, testProduct.Name, "approved")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		looser := uat()
		looser.Tier = "peek"
		h.b.policy = looser
		h.s.CheckPolicy()
		if rollbackFails {
			hb.failAfter = 1 // the new policy applies, the rollback fails
		}
		h.io.answers = []string{"y"}
		h.s.Command(context.Background(), ":review")
		if h.s.Policy().(fakePolicy).Tier != "read" {
			t.Fatal("unsaved loosening in force")
		}
		last := hb.applied[len(hb.applied)-1]
		_, ended := h.s.Ended()
		if rollbackFails {
			if !ended || last.Tier != "peek" {
				t.Fatalf("rollback failed: ended %v, backend on %+v", ended, last)
			}
		} else if ended || last.Tier != "read" {
			t.Fatalf("rollback: ended %v, backend on %+v", ended, last)
		}
	}
}

// A ConnectionComparer adds to the console's check: a host change ends the
// session whatever it says.
func TestHooksComparerAddsToHostCheck(t *testing.T) {
	h, _ := newHookHarness(t, uat(), nil)
	moved := uat()
	moved.Host = "other.example.com" // MaxRows stays 20: the comparer says no change
	h.b.policy = moved
	h.s.CheckPolicy()
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	if reason, ended := h.s.Ended(); !ended || reason != "connection settings changed" {
		t.Fatalf("ended %v %q", ended, reason)
	}
}

// piiApplyBackend is a PII backend that refuses policies once err is set.
type piiApplyBackend struct {
	*piiBackend
	err error
}

func (b *piiApplyBackend) ApplyPolicy(Policy) error { return b.err }

// A tightening that cannot be saved still applies (going back to the
// looser policy would fail open), with or without a PolicyApplier, and is
// audited; a loosening that cannot be saved stays out.
func TestTighteningSaveFailureStaysInForce(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes a read-only directory")
	}
	for _, hooks := range []bool{false, true} {
		var h *harness
		var hb *hookBackend
		if hooks {
			h, hb = newHookHarness(t, uat(), nil)
		} else {
			h = newHarness(t, uat(), nil)
		}
		dir := filepath.Join(h.state, testProduct.Name, "approved")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		tighter := uat()
		tighter.MaxRows = 10
		h.b.policy = tighter
		h.s.CheckPolicy()
		if h.s.Policy().(fakePolicy).MaxRows != 10 {
			t.Fatalf("hooks %v: unsaved tightening not in force", hooks)
		}
		if hooks && hb.applied[len(hb.applied)-1].MaxRows != 10 {
			t.Fatal("backend not on the tightened policy")
		}
		if _, ended := h.s.Ended(); ended {
			t.Fatalf("hooks %v: session ended", hooks)
		}
		found := false
		for _, r := range h.records(t) {
			if r["decision"] == "unsaved" && strings.Contains(fmt.Sprint(r["error"]), "tightened policy not saved") {
				found = true
			}
		}
		if !found || !strings.Contains(h.io.plain(), "the tightened policy applies, but could not be saved") {
			t.Fatalf("hooks %v: not told or audited:\n%s", hooks, h.io.plain())
		}
		// The loosening that follows cannot be saved: it stays out.
		looser := tighter
		looser.Tier = "peek"
		h.b.policy = looser
		h.s.CheckPolicy()
		h.io.answers = []string{"y"}
		h.s.Command(context.Background(), ":review")
		if h.s.Policy().(fakePolicy).Tier != "read" {
			t.Fatalf("hooks %v: unsaved loosening in force", hooks)
		}
		if hooks && hb.applied[len(hb.applied)-1].Tier != "read" {
			t.Fatal("backend left on the unsaved loosening")
		}
	}
}
