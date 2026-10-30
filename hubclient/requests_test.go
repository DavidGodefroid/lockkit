package hubclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/lockkit/ticket/devicetest"
)

type clk struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clk) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clk) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newClockEnv is newEnv with one clock for the store and the client.
func newClockEnv(t *testing.T, mod func(*hubclient.Config)) (*env, *clk) {
	t.Helper()
	c := &clk{t: time.Now().UTC().Truncate(time.Millisecond)}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := hubtest.New(t, inst, pub)
	st, err := plans.Open(filepath.Join(t.TempDir(), "plans"), plans.WithClock(c.now))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := hubclient.Config{URL: h.URL(), Instance: inst, Key: priv, HubKey: h.Pub, Now: c.now,
		StateFile: filepath.Join(t.TempDir(), "hub-state.json")}
	if mod != nil {
		mod(&cfg)
	}
	cl, err := hubclient.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &env{hub: h, client: cl, store: st, cfg: cfg, lockPub: pub}, c
}

var clearScreen = &ticket.Screen{Header: "db / crm · write", Body: []string{"UPDATE customers SET email = 'jane.doe@example.com'"}}

func facadeKeys(t *testing.T) (ed25519.PrivateKey, []ticket.PinnedFacade) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return priv, []ticket.PinnedFacade{{Facade: ticket.FacadeTTY, Key: pub}}
}

// poll runs one Poll and HandleRequests.
func poll(t *testing.T, e *env) error {
	t.Helper()
	if _, err := e.client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	return e.client.HandleRequests(context.Background(), e.store)
}

func submittedClear(t *testing.T, e *env) (*plans.Plan, *ticket.Ticket) {
	t.Helper()
	p, tk := e.plan(t, planHash)
	id, err := e.client.SubmitClear(context.Background(), e.store, p.ID, caller, tk, screen(), clearScreen)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(id))
	if err != nil {
		t.Fatal(err)
	}
	return p, signed
}

// Ctrl-O: the clear screen reaches the facade sealed to its ephemeral key;
// the hub sees ciphertext only, in the ticket as in the answer.
func TestRevealSealedToPinnedFacade(t *testing.T) {
	fkey, pins := facadeKeys(t)
	e := newEnv(t, func(c *hubclient.Config) { c.Facades = pins })
	_, tk := submittedClear(t, e)
	rk, priv, err := ticket.NewRevealKey(fkey, ticket.FacadeTTY, tk, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var seen []*ticket.HubRequest
	e.client.OnRequest(func(q *ticket.HubRequest, _ string, err error) {
		if err != nil {
			t.Errorf("request refused: %v", err)
		}
		seen = append(seen, q)
	})
	id := e.hub.Request(tk.ID, ticket.RequestReveal, rk, nil)
	if err := poll(t, e); err != nil {
		t.Fatal(err)
	}
	ans := e.hub.Answer(id)
	for _, b := range [][]byte{ans, e.hub.Ticket(tk.ID)} {
		if b == nil || strings.Contains(string(b), "jane.doe") {
			t.Fatalf("the hub saw: %s", b)
		}
	}
	var a struct {
		Reveal json.RawMessage `json:"reveal"`
	}
	if err := json.Unmarshal(ans, &a); err != nil || a.Reveal == nil {
		t.Fatalf("answer %s", ans)
	}
	s, err := ticket.OpenReveal(e.lockPub, priv, rk, a.Reveal)
	if err != nil || s.Body[0] != clearScreen.Body[0] {
		t.Fatalf("%+v %v", s, err)
	}
	if len(seen) != 1 || seen[0].Kind != ticket.RequestReveal {
		t.Fatalf("OnRequest %v", seen)
	}
	// The same request polled again is not answered twice.
	e.hub.Requeue(id)
	if err := poll(t, e); err != nil || len(seen) != 1 || e.hub.Answer(id) != nil {
		t.Fatalf("replayed: %v, %d", err, len(seen))
	}
}

func TestRevealRefused(t *testing.T) {
	fkey, pins := facadeKeys(t)
	otherKey, _ := facadeKeys(t)
	cases := map[string]struct {
		pins []ticket.PinnedFacade
		key  ed25519.PrivateKey
		mod  func(*ticket.HubRequest)
		want string
	}{
		"no pinned facade":   {nil, fkey, nil, hubclient.CodeFacadeRefused},
		"unpinned facade":    {pins, otherKey, nil, hubclient.CodeFacadeRefused},
		"stale":              {pins, fkey, func(q *ticket.HubRequest) { q.At = q.At.Add(-time.Hour) }, ""},
		"for other instance": {pins, fkey, func(q *ticket.HubRequest) { q.Instance = "other"; q.Reveal = nil; q.Kind = ticket.RequestRenew }, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, func(cfg *hubclient.Config) { cfg.Facades = c.pins })
			_, tk := submittedClear(t, e)
			rk, _, _ := ticket.NewRevealKey(c.key, ticket.FacadeTTY, tk, time.Now())
			id := e.hub.Request(tk.ID, ticket.RequestReveal, rk, c.mod)
			err := poll(t, e)
			if !errors.Is(err, hubclient.ErrBadRequest) {
				t.Fatalf("err %v", err)
			}
			ans := string(e.hub.Answer(id))
			if c.want == "" {
				if ans != "" {
					t.Fatalf("answered a request for another instance: %s", ans)
				}
				return
			}
			if !strings.Contains(ans, `"error"`) || !strings.Contains(ans, c.want) || strings.Contains(ans, "box") {
				t.Fatalf("answer %s", ans)
			}
		})
	}
}

// A request not signed by the pinned hub key is dropped unanswered.
func TestForgedRequestDropped(t *testing.T) {
	fkey, pins := facadeKeys(t)
	e := newEnv(t, func(c *hubclient.Config) { c.Facades = pins })
	_, tk := submittedClear(t, e)
	rk, _, _ := ticket.NewRevealKey(fkey, ticket.FacadeTTY, tk, time.Now())
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Millisecond)
	q := &ticket.HubRequest{V: ticket.Version, ID: ticket.NewID(now), Kind: ticket.RequestReveal, Ticket: tk.ID, Instance: inst,
		KeyID: tk.Source.KeyID, Facade: ticket.FacadeTTY, At: now, Reveal: rk}
	if err := q.Sign(forger); err != nil {
		t.Fatal(err)
	}
	b, _ := q.Marshal()
	e.hub.RawRequest(q.ID, b)
	if err := poll(t, e); !errors.Is(err, hubclient.ErrBadRequest) {
		t.Fatalf("%v", err)
	}
	if e.hub.Answer(q.ID) != nil {
		t.Fatal("answered a forged request")
	}
}

// An approval that aged before the run: the agent's run gets
// ticket.ErrExpired, Renew asks again with what changed, the new ticket
// runs once approved.
func TestRenewAgedApproval(t *testing.T) {
	e, c := newClockEnv(t, nil)
	ctx := context.Background()
	p, tk := e.plan(t, planHash)
	tk.Expires = nil // the ticket waits; the approval ages
	id, err := e.client.SubmitClear(ctx, e.store, p.ID, caller, tk, screen(), clearScreen)
	if err != nil {
		t.Fatal(err)
	}
	at := c.now()
	e.hub.DecideWith(id, ticket.Approved, "", nil, func(d *ticket.Decision) { d.At = at })
	if _, err := e.client.Poll(ctx, 0); err != nil {
		t.Fatal(err)
	}
	c.add(25 * time.Hour)
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, ticket.ErrExpired) {
		t.Fatalf("aged approval: %v", err)
	}
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, ticket.ErrExpired) {
		t.Fatalf("again: %v", err)
	}
	newHash := "sha256:" + strings.Repeat("9", 64)
	e.client.SetRecompute(func(sp *plans.Plan) (string, string, map[string]string, error) {
		return policyFP, newHash, nil, nil
	})
	if _, err := e.client.Renew(ctx, e.store, id, plans.Caller{UID: caller.UID, Token: "another agent"}); !errors.Is(err, hubclient.ErrNotRenewable) {
		t.Fatalf("another agent renewed: %v", err)
	}
	n, err := e.client.Renew(ctx, e.store, id, caller)
	if err != nil || n == "" || n == id {
		t.Fatalf("renew %q %v", n, err)
	}
	if again, err := e.client.Renew(ctx, e.store, id, caller); err != nil || again != n {
		t.Fatalf("renew twice: %q %v", again, err)
	}
	rt, err := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(n))
	if err != nil {
		t.Fatal(err)
	}
	r := rt.Renews
	if r == nil || r.Of != id || r.Reason != ticket.RenewApprovalExpired || r.ApprovedAt == nil || !r.ApprovedAt.Equal(at) ||
		!r.Checked || len(r.Changes) != 1 || r.Changes[0].Input != "plan_hash" || r.Changes[0].Change != ticket.ChangeChanged || rt.PlanHash != newHash {
		t.Fatalf("renewal %+v", r)
	}
	if rt.Screen.Header != tk.Screen.Header || strings.Contains(string(e.hub.Ticket(n)), "jane.doe") {
		t.Fatalf("screen %+v", rt.Screen)
	}
	e.hub.DecideWith(n, ticket.Approved, "", nil, func(d *ticket.Decision) { d.At = c.now() })
	if _, err := e.client.Poll(ctx, 0); err != nil {
		t.Fatal(err)
	}
	run, _, err := e.client.Begin(e.store, n, caller, recheck(policyFP, newHash))
	if err != nil {
		t.Fatal(err)
	}
	if run.Renews != p.ID || run.Clear == nil || run.Clear.Body[0] != clearScreen.Body[0] {
		t.Fatalf("renewal plan %+v", run)
	}
}

// A pending ticket that expired is renewed on the human's request from the
// hub, with no agent; inputs the product records give a named diff.
func TestRenewRequestFromHub(t *testing.T) {
	e, c := newClockEnv(t, nil)
	ctx := context.Background()
	before := map[string]string{"sql": "sha256:" + strings.Repeat("a", 64), "schema": "sha256:" + strings.Repeat("b", 64)}
	p, err := e.store.Create(plans.Binding{UID: caller.UID, Agent: "dev-1", TokenHash: plans.HashToken(caller.Token),
		PolicyFP: policyFP, PlanHash: planHash, Inputs: before}, json.RawMessage(`{}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql"}, ticket.RiskWrite, planHash, policyFP, c.now(), time.Hour)
	id, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	if err != nil {
		t.Fatal(err)
	}
	c.add(2 * time.Hour) // the ticket expired, undecided
	after := map[string]string{"sql": before["sql"], "schema": "sha256:" + strings.Repeat("c", 64)}
	e.client.SetRecompute(func(*plans.Plan) (string, string, map[string]string, error) {
		return policyFP, "sha256:" + strings.Repeat("8", 64), after, nil
	})
	rid := e.hub.Request(id, ticket.RequestRenew, nil, func(q *ticket.HubRequest) { q.At = c.now() })
	if err := poll(t, e); err != nil {
		t.Fatal(err)
	}
	var a struct{ Ticket, Error string }
	if err := json.Unmarshal(e.hub.Answer(rid), &a); err != nil || a.Ticket == "" {
		t.Fatalf("answer %s", e.hub.Answer(rid))
	}
	rt, err := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(a.Ticket))
	if err != nil {
		t.Fatal(err)
	}
	if r := rt.Renews; r.Reason != ticket.RenewExpired || r.ApprovedAt != nil || len(r.Changes) != 1 || r.Changes[0].Input != "schema" {
		t.Fatalf("renewal %+v", r)
	}
	// The agent's own run of the old ticket now points at the renewal.
	if n, err := e.client.Renew(ctx, e.store, id, caller); err != nil || n != a.Ticket {
		t.Fatalf("agent renew: %q %v", n, err)
	}
	// A pending ticket is not renewed.
	rid2 := e.hub.Request(a.Ticket, ticket.RequestRenew, nil, func(q *ticket.HubRequest) { q.At = c.now() })
	if err := poll(t, e); err == nil || !strings.Contains(string(e.hub.Answer(rid2)), "error") {
		t.Fatalf("renewed a pending ticket: %v %s", err, e.hub.Answer(rid2))
	}
}

// Without Recompute a renewal keeps the plan hash and says it was not
// checked: no facade may present it as unchanged.
func TestRenewUnchecked(t *testing.T) {
	e, c := newClockEnv(t, nil)
	ctx := context.Background()
	p, tk := e.plan(t, planHash)
	id, _ := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	c.add(2 * time.Hour)
	n, err := e.client.Renew(ctx, e.store, id, caller)
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(n))
	if rt.Renews.Checked || rt.Renews.Unchanged() || rt.PlanHash != planHash {
		t.Fatalf("%+v", rt.Renews)
	}
}

// The hub hears a fixed code for a failed request, never the error text:
// a recheck error can hold plan inputs.
func TestRequestErrorIsACodeOnly(t *testing.T) {
	e, c := newClockEnv(t, nil)
	ctx := context.Background()
	p, tk := e.plan(t, planHash)
	id, _ := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	c.add(2 * time.Hour)
	const canary = "CANARY jane.doe@example.com SELECT secret"
	e.client.SetRecompute(func(*plans.Plan) (string, string, map[string]string, error) {
		return "", "", nil, errors.New(canary)
	})
	var local error
	e.client.OnRequest(func(_ *ticket.HubRequest, _ string, err error) { local = err })
	rid := e.hub.Request(id, ticket.RequestRenew, nil, func(q *ticket.HubRequest) { q.At = c.now() })
	if err := poll(t, e); err == nil {
		t.Fatal("no error")
	}
	ans := string(e.hub.Answer(rid))
	if ans != `{"error":"`+hubclient.CodeRecheckFailed+`"}` || strings.Contains(ans, "CANARY") {
		t.Fatalf("answer %s", ans)
	}
	if local == nil || !strings.Contains(local.Error(), "CANARY") {
		t.Fatalf("the lock lost the detail: %v", local)
	}
}

// A renewal whose first submission failed (rate limit) is submitted again
// with the changes of the stored bindings: never "nothing changed" for a
// plan whose inputs moved. Changes name inputs only: the hub never gets a
// value, nor a digest it could test guesses against.
func TestRenewRetryKeepsChanges(t *testing.T) {
	e, c := newClockEnv(t, func(cfg *hubclient.Config) { cfg.RateN = 1 })
	ctx := context.Background()
	before := map[string]string{"user": "sha256:" + strings.Repeat("a", 64)}
	p, err := e.store.Create(plans.Binding{UID: caller.UID, TokenHash: plans.HashToken(caller.Token),
		PolicyFP: policyFP, PlanHash: planHash, Inputs: before}, json.RawMessage(`{}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	tk := ticket.NewTicket(ticket.Source{Lock: "locksql"}, ticket.RiskWrite, planHash, policyFP, c.now(), time.Hour)
	id, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	if err != nil {
		t.Fatal(err)
	}
	c.add(2 * time.Hour)
	digest, _ := ticket.HashOf("jane.doe")
	e.client.SetRecompute(func(*plans.Plan) (string, string, map[string]string, error) {
		return policyFP, "sha256:" + strings.Repeat("7", 64), map[string]string{"user": digest}, nil
	})
	// Fill the rate window with another ticket, then renew: limited.
	q, tk2 := e.plan(t, "sha256:"+strings.Repeat("6", 64))
	tk2.Created, tk2.Expires = c.now(), nil
	if _, err := e.client.Submit(ctx, e.store, q.ID, caller, tk2, screen()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.Renew(ctx, e.store, id, caller); !errors.Is(err, hubclient.ErrRateLimited) {
		t.Fatalf("first renewal: %v", err)
	}
	// The retry, from a recompute that now says nothing moved.
	e.client.SetRecompute(func(*plans.Plan) (string, string, map[string]string, error) { return policyFP, planHash, before, nil })
	c.add(hubclient.RateWindow)
	n, err := e.client.Renew(ctx, e.store, id, caller)
	if err != nil {
		t.Fatal(err)
	}
	raw := e.hub.Ticket(n)
	rt, _ := ticket.VerifyTicket(e.lockPub, raw)
	if rt.Renews.Unchanged() || len(rt.Renews.Changes) != 1 || rt.Renews.Changes[0].Input != "user" {
		t.Fatalf("retry lost the changes: %+v", rt.Renews)
	}
	if strings.Contains(string(raw), digest) || strings.Contains(string(raw), "jane.doe") {
		t.Fatal("the hub can test a guess against the ticket")
	}
}

// A policy that changed since the plan is no renewal: the risk class came
// from the old one.
func TestRenewRefusesChangedPolicy(t *testing.T) {
	e, c := newClockEnv(t, nil)
	ctx := context.Background()
	p, tk := e.plan(t, planHash)
	id, _ := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	c.add(2 * time.Hour)
	e.client.SetRecompute(func(*plans.Plan) (string, string, map[string]string, error) {
		return "sha256:" + strings.Repeat("5", 64), planHash, nil, nil
	})
	if _, err := e.client.Renew(ctx, e.store, id, caller); !errors.Is(err, hubclient.ErrNotRenewable) || hubclient.AnswerCode(err) != hubclient.CodePolicyChanged {
		t.Fatalf("%v", err)
	}
}

// Concurrent renewals of one expired ticket give one renewal.
func TestRenewConcurrent(t *testing.T) {
	e, c := newClockEnv(t, nil)
	ctx := context.Background()
	p, tk := e.plan(t, planHash)
	id, _ := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	c.add(2 * time.Hour)
	var wg sync.WaitGroup
	got := make([]string, 8)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], _ = e.client.Renew(ctx, e.store, id, caller)
		}()
	}
	wg.Wait()
	for _, g := range got {
		if g == "" || g != got[0] {
			t.Fatalf("renewals %v", got)
		}
	}
}

// An approval that aged while the agent was away is renewed on the human's
// request, before the agent runs it again.
func TestRenewRequestAgesOutApproval(t *testing.T) {
	e, c := newClockEnv(t, nil)
	ctx := context.Background()
	p, tk := e.plan(t, planHash)
	tk.Expires = nil
	id, _ := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	at := c.now()
	e.hub.DecideWith(id, ticket.Approved, "", nil, func(d *ticket.Decision) { d.At = at })
	if _, err := e.client.Poll(ctx, 0); err != nil {
		t.Fatal(err)
	}
	// Still usable: not renewed.
	rid := e.hub.Request(id, ticket.RequestRenew, nil, func(q *ticket.HubRequest) { q.At = c.now() })
	if err := poll(t, e); err == nil || !strings.Contains(string(e.hub.Answer(rid)), hubclient.CodeNotRenewable) {
		t.Fatalf("renewed a usable approval: %v %s", err, e.hub.Answer(rid))
	}
	c.add(25 * time.Hour)
	rid = e.hub.Request(id, ticket.RequestRenew, nil, func(q *ticket.HubRequest) { q.At = c.now() })
	if err := poll(t, e); err != nil {
		t.Fatal(err)
	}
	var a struct{ Ticket string }
	_ = json.Unmarshal(e.hub.Answer(rid), &a)
	rt, err := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(a.Ticket))
	if err != nil || rt.Renews.Reason != ticket.RenewApprovalExpired || !rt.Renews.ApprovedAt.Equal(at) {
		t.Fatalf("%+v %v", rt, err)
	}
	// The agent's run of the old ticket now points at the renewal.
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, ticket.ErrExpired) {
		t.Fatalf("begin: %v", err)
	}
	if n, err := e.client.Renew(ctx, e.store, id, caller); err != nil || n != a.Ticket {
		t.Fatalf("%q %v", n, err)
	}
}

// An aged approval that Begin would not honour (no device signature for a
// risk that needs one) is not turned into an approval-expired renewal.
func TestRenewRequestAgedApprovalNeedsDevice(t *testing.T) {
	phone := devicetest.New(rpID, origin, "phone")
	e, c := newClockEnv(t, func(cfg *hubclient.Config) {
		cfg.Devices, cfg.RequireDevice = []ticket.Device{phone.Device()}, []ticket.Risk{ticket.RiskWrite}
	})
	ctx := context.Background()
	p, tk := e.plan(t, planHash)
	tk.Expires = nil
	id, _ := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	at := c.now()
	e.hub.DecideWith(id, ticket.Approved, "", nil, func(d *ticket.Decision) { d.At = at })
	_, _ = e.client.Poll(ctx, 0)
	c.add(25 * time.Hour)
	rid := e.hub.Request(id, ticket.RequestRenew, nil, func(q *ticket.HubRequest) { q.At = c.now() })
	_ = poll(t, e)
	if !strings.Contains(string(e.hub.Answer(rid)), hubclient.CodeNotRenewable) {
		t.Fatalf("renewed a hub-only approval of a device risk: %s", e.hub.Answer(rid))
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Pending {
		t.Fatalf("plan is %s", sp.State)
	}
}

// A renewal whose plan already ran is not renewable; one whose renewal
// expired too is renewed in turn.
func TestRenewOfARenewal(t *testing.T) {
	e, c := newClockEnv(t, nil)
	ctx := context.Background()
	p, tk := e.plan(t, planHash)
	id, _ := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	c.add(2 * time.Hour)
	n, err := e.client.Renew(ctx, e.store, id, caller)
	if err != nil {
		t.Fatal(err)
	}
	c.add(25 * time.Hour) // the renewal expires undecided
	n2, err := e.client.Renew(ctx, e.store, id, caller)
	if err != nil || n2 == n || n2 == id {
		t.Fatalf("chain: %q %v", n2, err)
	}
	rt, _ := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(n2))
	if rt.Renews.Of != n {
		t.Fatalf("renews %s, want %s", rt.Renews.Of, n)
	}
	e.hub.DecideWith(n2, ticket.Approved, "", nil, func(d *ticket.Decision) { d.At = c.now() })
	_, _ = e.client.Poll(ctx, 0)
	run, _, err := e.client.Begin(e.store, n2, caller, recheck(policyFP, planHash))
	if err != nil {
		t.Fatal(err)
	}
	_ = e.client.Finish(ctx, e.store, run.ID, caller, true, "")
	if _, err := e.client.Renew(ctx, e.store, id, caller); !errors.Is(err, hubclient.ErrNotRenewable) {
		t.Fatalf("renewed a plan that ran: %v", err)
	}
}

// An input Recompute could not check shows as unchecked: never one click.
func TestRenewUncheckedInput(t *testing.T) {
	e, c := newClockEnv(t, nil)
	ctx := context.Background()
	before := map[string]string{"queue": "sha256:" + strings.Repeat("a", 64)}
	p, err := e.store.Create(plans.Binding{UID: caller.UID, TokenHash: plans.HashToken(caller.Token),
		PolicyFP: policyFP, PlanHash: planHash, Inputs: before}, json.RawMessage(`{}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	tk := ticket.NewTicket(ticket.Source{Lock: "lockmq"}, ticket.RiskWrite, planHash, policyFP, c.now(), time.Hour)
	id, _ := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	c.add(2 * time.Hour)
	e.client.SetRecompute(func(*plans.Plan) (string, string, map[string]string, error) {
		return policyFP, planHash, map[string]string{"queue": ticket.UncheckedInput}, nil
	})
	n, err := e.client.Renew(ctx, e.store, id, caller)
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(n))
	if rt.Renews.Unchanged() || len(rt.Renews.Changes) != 1 || rt.Renews.Changes[0].Change != ticket.ChangeUnchecked {
		t.Fatalf("%+v", rt.Renews)
	}
}
