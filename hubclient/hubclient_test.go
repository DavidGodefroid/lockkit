package hubclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
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
