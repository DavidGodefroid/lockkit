package hubclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"
)

const inst = "crm-prod"

var (
	planHash = "sha256:" + strings.Repeat("1", 64)
	policyFP = "sha256:" + strings.Repeat("2", 64)
	caller   = plans.Caller{UID: 1000, Token: "tok-dev-1"}
)

type env struct {
	hub     *hubtest.Hub
	client  *hubclient.Client
	store   *plans.Store
	cfg     hubclient.Config
	lockPub ed25519.PublicKey
}

func newEnv(t *testing.T, mod func(*hubclient.Config)) *env {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := hubtest.New(t, inst, pub)
	st, err := plans.Open(filepath.Join(t.TempDir(), "plans"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := hubclient.Config{URL: h.URL(), Instance: inst, Key: priv, HubKey: h.Pub,
		StateFile: filepath.Join(t.TempDir(), "hub-state.json")}
	if mod != nil {
		mod(&cfg)
	}
	c, err := hubclient.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &env{hub: h, client: c, store: st, cfg: cfg, lockPub: pub}
}

// plan makes a plan with hash and the ticket for it.
func (e *env) plan(t *testing.T, hash string) (*plans.Plan, *ticket.Ticket) {
	t.Helper()
	p, err := e.store.Create(plans.Binding{UID: caller.UID, Agent: "dev-1", TokenHash: plans.HashToken(caller.Token),
		PolicyFP: policyFP, PlanHash: hash}, json.RawMessage(`{"sql":"UPDATE t SET a = 1"}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql"}, ticket.RiskWrite, hash, policyFP, time.Now(), time.Hour)
	tk.Workspace, tk.Requester = "~/Documents", ticket.Requester{Agent: "dev-1", Session: "s1"}
	return p, tk
}

func screen() render.MaskedScreen {
	return render.MaskScreen(render.ScreenSource{
		Header: "db / crm · write",
		Body: []render.Line{{{Text: "UPDATE customers SET email = "},
			{Text: "jane.doe@example.com", Value: true, Column: "email", ColumnType: "text"}}},
	}, render.Masking{})
}

func recheck(policy, hash string) hubclient.Recheck {
	return func(*plans.Plan) (string, string, error) { return policy, hash, nil }
}

func TestNewRefusesUnpinnedHub(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	for name, cfg := range map[string]hubclient.Config{
		"no hub key":   {URL: "http://hub", Instance: inst, Key: priv, StateFile: "s"},
		"bad hub key":  {URL: "http://hub", Instance: inst, Key: priv, HubKey: pub[:8], StateFile: "s"},
		"no lock key":  {URL: "http://hub", Instance: inst, HubKey: pub, StateFile: "s"},
		"no url":       {Instance: inst, Key: priv, HubKey: pub, StateFile: "s"},
		"no instance":  {URL: "http://hub", Key: priv, HubKey: pub, StateFile: "s"},
		"bad instance": {URL: "http://hub", Instance: "../x", Key: priv, HubKey: pub, StateFile: "s"},
		"no state":     {URL: "http://hub", Instance: inst, Key: priv, HubKey: pub},
	} {
		if _, err := hubclient.New(cfg); err == nil {
			t.Errorf("%s: New accepted the config", name)
		}
	}
}

func TestHello(t *testing.T) {
	e := newEnv(t, nil)
	h, err := e.client.Hello(context.Background())
	if err != nil || h.Name != "lockhub" || h.API != 1 {
		t.Fatalf("hello: %+v %v", h, err)
	}
}

func TestSubmitPushesSignedMaskedTicket(t *testing.T) {
	e := newEnv(t, nil)
	p, tk := e.plan(t, planHash)
	id, err := e.client.Submit(context.Background(), e.store, p.ID, caller, tk, screen())
	if err != nil {
		t.Fatal(err)
	}
	raw := e.hub.Ticket(id)
	if raw == nil {
		t.Fatal("hub has no ticket")
	}
	if strings.Contains(string(raw), "jane.doe") {
		t.Fatalf("clear personal value in the pushed ticket: %s", raw)
	}
	got, err := ticket.VerifyTicket(e.lockPub, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source.Instance != inst || got.Source.KeyID != ticket.KeyID(e.lockPub) ||
		len(got.PII.Touched) == 0 || got.Screen.Header != "db / crm · write" {
		t.Errorf("pushed ticket: %+v", got)
	}
	sp, _ := e.store.Get(p.ID, caller)
	if sp.State != plans.Pending || sp.Ticket != id {
		t.Errorf("plan after submit: %s %s", sp.State, sp.Ticket)
	}
}

func TestSubmitRefusesUnmaskedScreen(t *testing.T) {
	e := newEnv(t, nil)
	p, tk := e.plan(t, planHash)
	_, err := e.client.Submit(context.Background(), e.store, p.ID, caller, tk, render.MaskedScreen{})
	if !errors.Is(err, render.ErrUnmasked) {
		t.Fatalf("err = %v, want ErrUnmasked", err)
	}
	if e.hub.Pushed() != 0 {
		t.Error("an unmasked ticket reached the hub")
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Planned {
		t.Errorf("plan is %s", sp.State)
	}
}

func TestSubmitIdempotentAndDeduped(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	p, tk := e.plan(t, planHash)
	id1, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	if err != nil {
		t.Fatal(err)
	}
	_, tk2 := e.plan(t, planHash)
	id2, err := e.client.Submit(ctx, e.store, p.ID, caller, tk2, screen())
	if err != nil || id2 != id1 {
		t.Fatalf("second run of the same plan: %s %v, want %s", id2, err, id1)
	}
	q, tk3 := e.plan(t, planHash)
	id3, err := e.client.Submit(ctx, e.store, q.ID, caller, tk3, screen())
	if err != nil || id3 != id1 {
		t.Fatalf("same plan hash: %s %v, want %s", id3, err, id1)
	}
	if n := e.hub.Pushed(); n != 1 {
		t.Errorf("hub got %d tickets, want 1", n)
	}
}

func TestHubDownIsPendingAndResumes(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.hub.Close()
	p, tk := e.plan(t, planHash)
	id, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	if !errors.Is(err, hubclient.ErrUnreachable) || id == "" {
		t.Fatalf("hub down: %q %v, want a ticket and ErrUnreachable", id, err)
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Pending {
		t.Fatalf("plan is %s, want pending", sp.State)
	}
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, hubclient.ErrPending) {
		t.Fatalf("begin with the hub down: %v, want ErrPending", err)
	}
	// The hub comes back on another address: a new client resends.
	h2 := hubtest.New(t, inst, e.lockPub)
	cfg := e.cfg
	cfg.URL, cfg.HubKey = h2.URL(), h2.Pub
	c2, err := hubclient.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.Sync(ctx, e.store); err != nil {
		t.Fatal(err)
	}
	if h2.Ticket(id) == nil {
		t.Fatal("pending ticket not resent")
	}
}

func TestRateLimitAndPendingCap(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, func(c *hubclient.Config) { c.RateN, c.MaxPending = 2, 10 })
	for i := 0; i < 2; i++ {
		p, tk := e.plan(t, "sha256:"+strings.Repeat(string(rune('a'+i)), 64))
		if _, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen()); err != nil {
			t.Fatal(err)
		}
	}
	p, tk := e.plan(t, "sha256:"+strings.Repeat("c", 64))
	if _, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen()); !errors.Is(err, hubclient.ErrRateLimited) {
		t.Fatalf("third ticket: %v, want ErrRateLimited", err)
	}
	if e.hub.Pushed() != 2 {
		t.Errorf("hub got %d tickets", e.hub.Pushed())
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Planned {
		t.Errorf("rate-limited plan is %s", sp.State)
	}

	e = newEnv(t, func(c *hubclient.Config) { c.MaxPending = 1 })
	p, tk = e.plan(t, "sha256:"+strings.Repeat("a", 64))
	if _, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen()); err != nil {
		t.Fatal(err)
	}
	p, tk = e.plan(t, "sha256:"+strings.Repeat("b", 64))
	if _, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen()); !errors.Is(err, hubclient.ErrRateLimited) {
		t.Fatalf("over the pending cap: %v, want ErrRateLimited", err)
	}
}

func TestHubTooManyPending(t *testing.T) {
	e := newEnv(t, nil)
	e.hub.SetPushStatus(http.StatusTooManyRequests)
	p, tk := e.plan(t, planHash)
	_, err := e.client.Submit(context.Background(), e.store, p.ID, caller, tk, screen())
	if !errors.Is(err, hubclient.ErrRateLimited) {
		t.Fatalf("429: %v, want ErrRateLimited", err)
	}
	var he *hubclient.HubError
	if !errors.As(err, &he) || he.Status != 429 {
		t.Errorf("not a HubError: %v", err)
	}
}

func TestWrongLockKeyRefused(t *testing.T) {
	e := newEnv(t, nil)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	e.hub.SetLockKey(other) // the hub pinned another key for the instance
	p, tk := e.plan(t, planHash)
	_, err := e.client.Submit(context.Background(), e.store, p.ID, caller, tk, screen())
	var he *hubclient.HubError
	if !errors.As(err, &he) || he.Status != 401 {
		t.Fatalf("err = %v, want a 401 HubError", err)
	}
}

func submitted(t *testing.T, e *env) (*plans.Plan, string) {
	t.Helper()
	p, tk := e.plan(t, planHash)
	id, err := e.client.Submit(context.Background(), e.store, p.ID, caller, tk, screen())
	if err != nil {
		t.Fatal(err)
	}
	return p, id
}

func TestApprovedRunsOnce(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	p, id := submitted(t, e)
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, hubclient.ErrPending) {
		t.Fatalf("before a decision: %v, want ErrPending", err)
	}
	e.hub.Decide(id, ticket.Approved, "")
	if n, err := e.client.Poll(ctx, 0); err != nil || n != 1 {
		t.Fatalf("poll: %d %v", n, err)
	}
	if _, _, err := e.client.Begin(e.store, id, plans.Caller{UID: 1000, Token: "other"}, recheck(policyFP, planHash)); !errors.Is(err, plans.ErrWrongRequester) {
		t.Fatalf("another agent: %v, want ErrWrongRequester", err)
	}
	got, d, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash))
	if err != nil || got.ID != p.ID || got.State != plans.Executing {
		t.Fatalf("begin: %+v %v", got, err)
	}
	if d == nil || d.Decision != ticket.Approved || d.Approver.ID != "host:uid:1000" || d.Facade != "tty" || d.Sig == "" {
		t.Fatalf("decision for the audit: %+v", d)
	}
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); err == nil {
		t.Fatal("the approval ran twice")
	}
	if err := e.client.Finish(ctx, e.store, p.ID, caller, true, ""); err != nil {
		t.Fatal(err)
	}
	if !e.hub.Consumed(id) {
		t.Error("consumed not sent to the hub")
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Executed {
		t.Errorf("plan is %s", sp.State)
	}
}

func TestForgedDecisionIgnored(t *testing.T) {
	e := newEnv(t, nil)
	_, id := submitted(t, e)
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	e.hub.DecideWith(id, ticket.Approved, "", forger, nil)
	n, err := e.client.Poll(context.Background(), 0)
	if n != 0 || !errors.Is(err, hubclient.ErrBadDecision) {
		t.Fatalf("poll of a forged decision: %d %v, want 0 and ErrBadDecision", n, err)
	}
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, hubclient.ErrPending) {
		t.Fatalf("forged approval: %v, want ErrPending", err)
	}
}

func TestDecisionForAnotherPlanRefused(t *testing.T) {
	e := newEnv(t, nil)
	p, id := submitted(t, e)
	e.hub.DecideWith(id, ticket.Approved, "", nil, func(d *ticket.Decision) { d.PlanHash = "sha256:" + strings.Repeat("9", 64) })
	if _, err := e.client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, hubclient.ErrBadDecision) {
		t.Fatalf("decision on another plan hash: %v, want ErrBadDecision", err)
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Pending {
		t.Errorf("plan is %s", sp.State)
	}
}

// TestPendingIsNotDenied pins the contract a product maps to the agent
// (lockkit#165): no decision yet is ErrPending and never ErrDenied (the
// agent waits and runs the ticket again); only a denial the hub signed is
// ErrDenied, and never ErrPending.
func TestPendingIsNotDenied(t *testing.T) {
	e := newEnv(t, nil)
	_, id := submitted(t, e)
	_, d, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash))
	if !errors.Is(err, hubclient.ErrPending) || errors.Is(err, hubclient.ErrDenied) || d != nil {
		t.Fatalf("no decision yet: %v %+v, want ErrPending only", err, d)
	}
	e.hub.Decide(id, ticket.Denied, "")
	if _, err := e.client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	_, d, err = e.client.Begin(e.store, id, caller, recheck(policyFP, planHash))
	if !errors.Is(err, hubclient.ErrDenied) || errors.Is(err, hubclient.ErrPending) || d == nil || d.Decision != ticket.Denied {
		t.Fatalf("denied: %v %+v, want ErrDenied only, with the decision", err, d)
	}
}

func TestDeniedEndsPlan(t *testing.T) {
	e := newEnv(t, nil)
	p, id := submitted(t, e)
	e.hub.Decide(id, ticket.Denied, "not today")
	if _, err := e.client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	_, d, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash))
	if !errors.Is(err, hubclient.ErrDenied) || !strings.Contains(err.Error(), "not today") {
		t.Fatalf("denied: %v", err)
	}
	if d == nil || d.Decision != ticket.Denied || d.Approver.ID == "" {
		t.Fatalf("denial for the audit: %+v", d)
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Denied {
		t.Errorf("plan is %s", sp.State)
	}
}

func TestStaleRecheck(t *testing.T) {
	e := newEnv(t, nil)
	p, id := submitted(t, e)
	e.hub.Decide(id, ticket.Approved, "")
	if _, err := e.client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	_, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, "sha256:"+strings.Repeat("9", 64)))
	if !errors.Is(err, plans.ErrStale) {
		t.Fatalf("moved plan: %v, want ErrStale", err)
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Stale {
		t.Errorf("plan is %s", sp.State)
	}
}

func TestCursorAndInboxPersisted(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	_, id := submitted(t, e)
	e.hub.Decide(id, ticket.Approved, "")
	if _, err := e.client.Poll(ctx, 0); err != nil {
		t.Fatal(err)
	}
	// The lock restarts before the agent comes back for the result.
	c2, err := hubclient.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Poll(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if got := e.hub.Sinces(); len(got) != 2 || got[0] != "0" || got[1] != "1" {
		t.Errorf("since sent: %v, want [0 1]", got)
	}
	if _, _, err := c2.Begin(e.store, id, caller, recheck(policyFP, planHash)); err != nil {
		t.Fatalf("decision lost by the restart: %v", err)
	}
}

func TestWithdraw(t *testing.T) {
	e := newEnv(t, nil)
	p, id := submitted(t, e)
	if err := e.client.Withdraw(context.Background(), e.store, p.ID, caller, "agent gave up"); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.hub.Withdrawn(id); r != "agent gave up" {
		t.Errorf("hub withdrawal reason: %q", r)
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Withdrawn {
		t.Errorf("plan is %s", sp.State)
	}
}

func TestWatchDeliversDecisions(t *testing.T) {
	e := newEnv(t, nil)
	_, id := submitted(t, e)
	e.hub.Decide(id, ticket.Approved, "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.client.Watch(ctx, e.store, nil); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash))
		if err == nil {
			return
		}
		if !errors.Is(err, hubclient.ErrPending) || time.Now().After(deadline) {
			t.Fatalf("watch did not deliver the decision: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Plans withdrawn while the lock ran without its hub are withdrawn at the
// hub by the next Sync, once; a hub that no longer knows the ticket is
// told all the same.
func TestSyncWithdrawsUntold(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	p, tk := e.plan(t, planHash)
	id, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	if err != nil {
		t.Fatal(err)
	}
	q, tk2 := e.plan(t, "sha256:"+strings.Repeat("3", 64))
	id2, err := e.client.Submit(ctx, e.store, q.ID, caller, tk2, screen())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.WithdrawAll("standalone"); err != nil {
		t.Fatal(err)
	}
	e.hub.SetWithdrawStatus(id2, http.StatusNotFound)
	r, tk3 := e.plan(t, "sha256:"+strings.Repeat("4", 64))
	id3, _ := e.client.Submit(ctx, e.store, r.ID, caller, tk3, screen())
	q4, tk4 := e.plan(t, "sha256:"+strings.Repeat("5", 64))
	id4, _ := e.client.Submit(ctx, e.store, q4.ID, caller, tk4, screen())
	_, _ = e.store.WithdrawAll("standalone")
	e.hub.SetWithdrawStatus(id3, http.StatusConflict)
	e.hub.SetWithdrawStatus(id4, http.StatusGone)
	if err := e.client.Sync(ctx, e.store); err != nil {
		t.Fatal(err)
	}
	if r, ok := e.hub.Withdrawn(id); !ok || r != "standalone" {
		t.Fatalf("withdrawn %q %v", r, ok)
	}
	if n := len(e.store.Untold()); n != 0 {
		t.Fatalf("%d untold left", n)
	}
	e.hub.SetWithdrawStatus(id, http.StatusServiceUnavailable)
	if err := e.client.Sync(ctx, e.store); err != nil {
		t.Fatalf("told twice: %v", err)
	}
}

// A hub that cannot be reached keeps the plan untold, for the next Sync.
func TestSyncUntoldHubDown(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	p, tk := e.plan(t, planHash)
	id, _ := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	_, _ = e.store.WithdrawAll("standalone")
	e.hub.SetWithdrawStatus(id, http.StatusServiceUnavailable)
	if err := e.client.Sync(ctx, e.store); !errors.Is(err, hubclient.ErrUnreachable) {
		t.Fatalf("Sync: %v", err)
	}
	if n := len(e.store.Untold()); n != 1 {
		t.Fatalf("%d untold", n)
	}
	e.hub.SetWithdrawStatus(id, 0)
	if err := e.client.Sync(ctx, e.store); err != nil || len(e.store.Untold()) != 0 {
		t.Fatalf("Sync: %v, %d untold", err, len(e.store.Untold()))
	}
}

// A ticket the human withdraws at the hub (lox run, lox withdraw) comes
// back as a denial whose reason starts with ticket.WithdrawnReason: the
// lock ends the plan Withdrawn as soon as it polls it, without waiting for
// the agent, and the agent's next run is told the human withdrew it.
func TestHubWithdrawalEndsPlanAtPoll(t *testing.T) {
	e := newEnv(t, nil)
	p, id := submitted(t, e)
	reason := ticket.WithdrawnReason + "david in lox run"
	e.hub.Decide(id, ticket.Denied, reason)
	if _, err := e.client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if err := e.client.EndDenied(e.store); err != nil {
		t.Fatal(err)
	}
	sp, _ := e.store.Get(p.ID, caller)
	if sp.State != plans.Withdrawn || sp.Reason != reason || sp.Untold {
		t.Fatalf("plan after the hub's withdrawal: %s %q untold=%v", sp.State, sp.Reason, sp.Untold)
	}
	if n := len(e.store.Pending()); n != 0 {
		t.Errorf("%d plans still pending", n)
	}
	_, d, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash))
	if !errors.Is(err, hubclient.ErrDenied) || !errors.Is(err, hubclient.ErrWithdrawn) ||
		!strings.Contains(err.Error(), "ticket withdrawn by the human") || !strings.Contains(err.Error(), "david in lox run") {
		t.Fatalf("agent's run after the withdrawal: %v", err)
	}
	if d == nil || d.Decision != ticket.Denied || d.Reason != reason {
		t.Fatalf("denial for the audit: %+v", d)
	}
	// Answered once, then the plan is only used.
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, plans.ErrUsed) {
		t.Errorf("second run: %v, want ErrUsed", err)
	}
}

func TestHubDenialEndsPlanAtPoll(t *testing.T) {
	e := newEnv(t, nil)
	p, id := submitted(t, e)
	e.hub.Decide(id, ticket.Denied, "not today")
	if _, err := e.client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if err := e.client.EndDenied(e.store); err != nil {
		t.Fatal(err)
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Denied || sp.Reason != "not today" {
		t.Fatalf("plan after the denial: %s %q", sp.State, sp.Reason)
	}
	_, d, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash))
	if !errors.Is(err, hubclient.ErrDenied) || errors.Is(err, hubclient.ErrWithdrawn) || !strings.Contains(err.Error(), "not today") || d == nil {
		t.Fatalf("agent's run after the denial: %v %+v", err, d)
	}
}

// A withdrawal that reaches Begin before EndDenied ran ends the plan
// Withdrawn too.
func TestHubWithdrawalAtBegin(t *testing.T) {
	e := newEnv(t, nil)
	p, id := submitted(t, e)
	e.hub.Decide(id, ticket.Denied, ticket.WithdrawnReason+"david in lox withdraw")
	if _, err := e.client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, hubclient.ErrWithdrawn) {
		t.Fatalf("run: %v, want ErrWithdrawn", err)
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Withdrawn {
		t.Errorf("plan is %s", sp.State)
	}
}

// EndDenied acts only on a denial that matches the lock's own ticket, and
// never on an approval.
func TestEndDeniedChecksTheDecision(t *testing.T) {
	e := newEnv(t, nil)
	p, id := submitted(t, e)
	e.hub.DecideWith(id, ticket.Denied, ticket.WithdrawnReason+"x", nil, func(d *ticket.Decision) { d.PlanHash = "sha256:" + strings.Repeat("9", 64) })
	if _, err := e.client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if err := e.client.EndDenied(e.store); !errors.Is(err, hubclient.ErrBadDecision) {
		t.Fatalf("denial on another plan hash: %v, want ErrBadDecision", err)
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Pending {
		t.Fatalf("plan is %s", sp.State)
	}

	q, id2 := submittedHash(t, e, "sha256:"+strings.Repeat("3", 64))
	e.hub.Decide(id2, ticket.Approved, "")
	if _, err := e.client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if err := e.client.EndDenied(e.store); err != nil {
		t.Fatal(err)
	}
	if sp, _ := e.store.Get(q.ID, caller); sp.State != plans.Pending {
		t.Fatalf("approved plan is %s", sp.State)
	}
}

// A withdrawal frees the pending slot of its plan: the lock takes a new
// request once the queue was full.
func TestHubWithdrawalFreesPendingSlot(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, func(c *hubclient.Config) { c.MaxPending = 2 })
	var ids []string
	for i := 0; i < 2; i++ {
		_, id := submittedHash(t, e, "sha256:"+strings.Repeat(string(rune('a'+i)), 64))
		ids = append(ids, id)
	}
	p, tk := e.plan(t, "sha256:"+strings.Repeat("c", 64))
	if _, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen()); !errors.Is(err, hubclient.ErrRateLimited) {
		t.Fatalf("queue full: %v, want ErrRateLimited", err)
	}
	for _, id := range ids {
		e.hub.Decide(id, ticket.Denied, ticket.WithdrawnReason+"david in lox run")
	}
	pushed := e.hub.Pushed()
	if _, err := e.client.Poll(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if err := e.client.EndDenied(e.store); err != nil {
		t.Fatal(err)
	}
	// A restarted lock (nothing acknowledged yet) pushes only what is
	// still pending.
	c2, err := hubclient.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.Sync(ctx, e.store); err != nil || e.hub.Pushed() != pushed {
		t.Fatalf("sync pushed withdrawn tickets again: %v, %d pushes, want %d", err, e.hub.Pushed(), pushed)
	}
	if _, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen()); err != nil {
		t.Fatalf("after the withdrawal: %v", err)
	}
}

// Watch ends a withdrawn plan without anyone running it.
func TestWatchEndsWithdrawnPlan(t *testing.T) {
	e := newEnv(t, nil)
	p, id := submitted(t, e)
	e.hub.Decide(id, ticket.Denied, ticket.WithdrawnReason+"david in lox run")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.client.Watch(ctx, e.store, nil); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if sp, _ := e.store.Get(p.ID, caller); sp.State == plans.Withdrawn {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Watch did not end the withdrawn plan")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A denial kept before a restart still ends its plan: the inbox is the
// state file's.
func TestEndDeniedAfterRestart(t *testing.T) {
	e := newEnv(t, nil)
	p, id := submitted(t, e)
	e.hub.Decide(id, ticket.Denied, ticket.WithdrawnReason+"david in lox run")
	if _, err := e.client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	c2, err := hubclient.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.EndDenied(e.store); err != nil {
		t.Fatal(err)
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Withdrawn {
		t.Errorf("plan is %s", sp.State)
	}
}

func submittedHash(t *testing.T, e *env, hash string) (*plans.Plan, string) {
	t.Helper()
	p, tk := e.plan(t, hash)
	id, err := e.client.Submit(context.Background(), e.store, p.ID, caller, tk, screen())
	if err != nil {
		t.Fatal(err)
	}
	return p, id
}

// EndDenied (Watch) ending the plan between Begin's read of it as pending
// and Begin's own End of it: Begin answers the denial with its reason,
// once, instead of a refused transition.
func TestBeginRacesEndDenied(t *testing.T) {
	for name, reason := range map[string]string{
		"denied":    "not today",
		"withdrawn": ticket.WithdrawnReason + "david in lox run",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			p, id := submitted(t, e)
			e.hub.Decide(id, ticket.Denied, reason)
			if _, err := e.client.Poll(context.Background(), 0); err != nil {
				t.Fatal(err)
			}
			restore := hubclient.SetBeforeDenialEnd(func() {
				if err := e.client.EndDenied(e.store); err != nil {
					t.Errorf("EndDenied: %v", err)
				}
			})
			defer restore()
			_, d, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash))
			if !errors.Is(err, hubclient.ErrDenied) || !strings.Contains(err.Error(), "david in lox run") && !strings.Contains(err.Error(), "not today") {
				t.Fatalf("run racing EndDenied: %v, want ErrDenied with the reason", err)
			}
			if errors.Is(err, hubclient.ErrWithdrawn) != (name == "withdrawn") {
				t.Errorf("ErrWithdrawn: %v", err)
			}
			if d == nil || d.Decision != ticket.Denied || d.Reason != reason {
				t.Fatalf("denial for the audit: %+v", d)
			}
			sp, _ := e.store.Get(p.ID, caller)
			if sp.Reason != reason || (name == "withdrawn") != (sp.State == plans.Withdrawn) {
				t.Errorf("plan is %s %q", sp.State, sp.Reason)
			}
			// Answered once: the next run is only told the plan is used.
			restore()
			if _, d, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, plans.ErrUsed) || d != nil {
				t.Errorf("second run: %+v %v, want ErrUsed and no denial", d, err)
			}
		})
	}
}

// Concurrent runs of a denied ticket, with Watch ending it: exactly one
// run answers the denial (the lock audits it once), the others ErrUsed.
func TestBeginDenialAnsweredOnce(t *testing.T) {
	e := newEnv(t, nil)
	_, id := submitted(t, e)
	e.hub.Decide(id, ticket.Denied, "not today")
	if _, err := e.client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	const n = 8
	errs := make(chan error, n+1)
	denials := make(chan *ticket.Decision, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			<-start
			_, d, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash))
			switch {
			case errors.Is(err, hubclient.ErrDenied) && d != nil:
				denials <- d
				errs <- nil
			case errors.Is(err, plans.ErrUsed) && d == nil:
				errs <- nil
			default:
				errs <- fmt.Errorf("run: %+v %v", d, err)
			}
		}()
	}
	go func() { <-start; errs <- e.client.EndDenied(e.store) }()
	close(start)
	for i := 0; i < n+1; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	if got := len(denials); got != 1 {
		t.Errorf("%d runs answered the denial, want 1", got)
	}
}
