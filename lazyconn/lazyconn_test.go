package lazyconn

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"
)

const inst = "crm-prod"

var policyFP = "sha256:" + strings.Repeat("2", 64)

// decider plays the hub and `lox run` in one: it signs the lock's ticket
// as hubclient.Ask would, verifies it under the lock key, decides with
// decide, seals the secret and signs the decision with the hub key.
type decider struct {
	t                *testing.T
	lockKey, hubKey  ed25519.PrivateKey
	lockPub, hubPub  ed25519.PublicKey
	secret           []byte
	gate             chan struct{} // when set, each Ask waits on it
	decide           func(tk *ticket.Ticket, d *ticket.Decision)
	asks             atomic.Int32
	consumed         atomic.Int32
	mu               sync.Mutex
	tickets, decided [][]byte
	last             *ticket.Ticket
}

func newDecider(t *testing.T) *decider {
	lpub, lkey, _ := ed25519.GenerateKey(rand.Reader)
	hpub, hkey, _ := ed25519.GenerateKey(rand.Reader)
	return &decider{t: t, lockKey: lkey, hubKey: hkey, lockPub: lpub, hubPub: hpub, secret: []byte("hunter2")}
}

func (x *decider) Ask(ctx context.Context, t *ticket.Ticket, screen render.MaskedScreen) (*ticket.Decision, error) {
	x.asks.Add(1)
	if !screen.Valid() {
		return nil, render.ErrUnmasked
	}
	t.Source.Instance, t.Source.KeyID = inst, ticket.KeyID(x.lockPub)
	t.Screen, t.PII.Touched = screen.Screen(), screen.Touched()
	if err := t.Sign(x.lockKey); err != nil {
		return nil, err
	}
	raw, _ := t.Marshal()
	if x.gate != nil {
		select {
		case <-x.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// The decider's side: it reads the ticket as the hub relayed it.
	tk, err := ticket.VerifyTicket(x.lockPub, raw)
	if err != nil {
		return nil, err
	}
	d := &ticket.Decision{V: ticket.VersionKinds, Ticket: tk.ID, Instance: tk.Source.Instance, KeyID: tk.Source.KeyID,
		PlanHash: tk.PlanHash, Decision: ticket.Approved, Approver: ticket.Approver{ID: "lox-run"}, Facade: "lox-run",
		At: time.Now().UTC().Truncate(time.Millisecond), Nonce: ticket.NewNonce(),
		Rule: &ticket.Rule{By: ticket.RuleAuto, ID: "dev-connect"}}
	if tk.Subject.SecretTo != "" {
		if d.Secret, err = ticket.SealSecret(tk, x.secret); err != nil {
			return nil, err
		}
	}
	if x.decide != nil {
		x.decide(tk, d)
	}
	if err := d.Sign(x.hubKey); err != nil {
		return nil, err
	}
	draw, _ := d.Marshal()
	x.mu.Lock()
	x.tickets, x.decided, x.last = append(x.tickets, raw), append(x.decided, draw), tk
	x.mu.Unlock()
	got, err := ticket.VerifyDecision(x.hubPub, draw)
	if err != nil {
		return nil, err
	}
	return got, got.Match(t)
}

func (x *decider) Consumed(context.Context, string) error { x.consumed.Add(1); return nil }

// conn is a fake backend connection.
type conn struct {
	profile string
	secret  string
	closed  atomic.Bool
}

func (c *conn) Close() error { c.closed.Store(true); return nil }

// timers is a manual clock for idle closes.
type timers struct {
	mu  sync.Mutex
	all []*timer
}

type timer struct {
	d       time.Duration
	f       func()
	stopped bool
}

func (t *timer) Stop() bool { was := !t.stopped; t.stopped = true; return was }

func (ts *timers) AfterFunc(d time.Duration, f func()) Timer {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	t := &timer{d: d, f: f}
	ts.all = append(ts.all, t)
	return t
}

// fire runs every timer not stopped (an idle period passing), and
// returns how many ran.
func (ts *timers) fire() int {
	ts.mu.Lock()
	var run []*timer
	for _, t := range ts.all {
		if !t.stopped {
			t.stopped = true
			run = append(run, t)
		}
	}
	ts.mu.Unlock()
	for _, t := range run {
		t.f()
	}
	return len(run)
}

// fireAll runs every timer ever set, stopped or not: a timer that fired
// while it was being stopped.
func (ts *timers) fireAll() {
	ts.mu.Lock()
	run := append([]*timer(nil), ts.all...)
	ts.mu.Unlock()
	for _, t := range run {
		t.f()
	}
}

type fixture struct {
	pool    *Pool[*conn]
	dec     *decider
	timers  *timers
	dials   atomic.Int32
	dialErr error
	prof    Profile
	mu      sync.Mutex
	events  []Event
}

func newFixture(t *testing.T, mod func(*fixture, *Config[*conn])) *fixture {
	t.Helper()
	f := &fixture{dec: newDecider(t), timers: &timers{},
		prof: Profile{Endpoint: "db.internal:5432/shop", Credential: ticket.CredentialAsk, NeedSecret: true, PolicyFP: policyFP}}
	cfg := Config[*conn]{
		Lock:  "locksql",
		Asker: f.dec,
		Profile: func(name string) (Profile, error) {
			if name == "missing" {
				return Profile{}, errors.New("no such profile")
			}
			return f.prof, nil
		},
		Dial: func(ctx context.Context, name string, g Grant) (*conn, error) {
			f.dials.Add(1)
			if f.dialErr != nil {
				return nil, f.dialErr
			}
			return &conn{profile: name, secret: string(g.Secret)}, nil
		},
		Idle:      time.Minute,
		AfterFunc: f.timers.AfterFunc,
		OnEvent:   func(e Event) { f.mu.Lock(); f.events = append(f.events, e); f.mu.Unlock() },
	}
	if mod != nil {
		mod(f, &cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.pool = p
	return f
}

func (f *fixture) kinds() []EventKind {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []EventKind
	for _, e := range f.events {
		out = append(out, e.Kind)
	}
	return out
}

var req = Request{Profile: "crm-prod", Requester: ticket.Requester{Agent: "dev-1", Session: "s-1"}, Note: "count orders"}

func TestStartsDisconnectedAndConnectsOnApproval(t *testing.T) {
	f := newFixture(t, nil)
	if f.pool.Connected("crm-prod") || f.dec.asks.Load() != 0 {
		t.Fatal("a pool connects before any request")
	}
	c, release, err := f.pool.Acquire(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if c.secret != "hunter2" || !f.pool.Connected("crm-prod") || f.dec.asks.Load() != 1 || f.dec.consumed.Load() != 1 {
		t.Fatalf("conn %+v asks %d", c, f.dec.asks.Load())
	}
	// The ticket: a version-2 connect ticket, with a masked screen and
	// no secret.
	tk := f.dec.last
	if tk.V != ticket.VersionKinds || tk.Kind != ticket.KindConnect || tk.Risk != ticket.RiskUnlock ||
		tk.Subject.Profile != "crm-prod" || tk.Subject.Endpoint != "db.internal:5432/shop" || tk.Subject.SecretTo == "" ||
		tk.Requester.Agent != "dev-1" || tk.Screen.Header != "crm-prod · connect" || tk.Expires == nil {
		t.Fatalf("ticket %+v %+v", tk, tk.Subject)
	}
	for _, b := range append(f.dec.tickets, f.dec.decided...) {
		if strings.Contains(string(b), "hunter2") {
			t.Fatalf("the secret left the lock in clear: %s", b)
		}
	}
	// The next request reuses the connection: no ticket.
	c2, release2, err := f.pool.Acquire(context.Background(), req)
	if err != nil || c2 != c || f.dec.asks.Load() != 1 {
		t.Fatalf("second acquire: %v asks %d", err, f.dec.asks.Load())
	}
	release2()
	release2() // idempotent
	if got := f.kinds(); len(got) != 1 || got[0] != EventConnected {
		t.Fatalf("events %v", got)
	}
	f.mu.Lock()
	ev := f.events[0]
	f.mu.Unlock()
	if ev.Decision == nil || ev.Decision.Rule.ID != "dev-connect" || ev.Ticket != tk.ID {
		t.Fatalf("event %+v", ev)
	}
}

func TestOneTicketPerProfileUnderConcurrency(t *testing.T) {
	f := newFixture(t, nil)
	f.dec.gate = make(chan struct{})
	var wg sync.WaitGroup
	conns := make([]*conn, 8)
	errs := make([]error, 8)
	releases := make([]func(), 8)
	for i := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conns[i], releases[i], errs[i] = f.pool.Acquire(context.Background(), req)
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(f.dec.gate)
	wg.Wait()
	for i := range conns {
		if errs[i] != nil || conns[i] != conns[0] {
			t.Fatalf("acquire %d: %v", i, errs[i])
		}
	}
	if f.dec.asks.Load() != 1 || f.dials.Load() != 1 {
		t.Fatalf("asks %d dials %d", f.dec.asks.Load(), f.dials.Load())
	}
	// Another profile has its own ticket and connection.
	other := req
	other.Profile = "crm-staging"
	c, rel, err := f.pool.Acquire(context.Background(), other)
	if err != nil || c == conns[0] || f.dec.asks.Load() != 2 {
		t.Fatalf("other profile: %v", err)
	}
	rel()
	for _, r := range releases {
		r()
	}
	// Idle: only the last release of each connection set a timer.
	if n := f.timers.fire(); n != 2 {
		t.Fatalf("%d idle timers", n)
	}
}

func TestIdleCloseThenAskAgain(t *testing.T) {
	f := newFixture(t, nil)
	c, release, err := f.pool.Acquire(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if f.timers.fire() != 0 {
		t.Fatal("an idle timer while the connection is in use")
	}
	release()
	f.timers.mu.Lock()
	d := f.timers.all[0].d
	f.timers.mu.Unlock()
	if d != time.Minute {
		t.Fatalf("idle timeout %s", d)
	}
	if f.timers.fire() != 1 || !c.closed.Load() || f.pool.Connected("crm-prod") {
		t.Fatal("not closed when idle")
	}
	// After the close, the next request asks again.
	c2, release2, err := f.pool.Acquire(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer release2()
	if c2 == c || f.dec.asks.Load() != 2 || f.dials.Load() != 2 {
		t.Fatalf("asks %d dials %d", f.dec.asks.Load(), f.dials.Load())
	}
	if got := f.kinds(); len(got) != 3 || got[1] != EventClosed {
		t.Fatalf("events %v", got)
	}
}

func TestUseBeforeIdleKeepsTheConnection(t *testing.T) {
	f := newFixture(t, nil)
	c, release, _ := f.pool.Acquire(context.Background(), req)
	release()
	// Used again before the idle timeout: the timer is stopped, and a
	// stale timer that fires anyway does not close it.
	_, release2, err := f.pool.Acquire(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	f.timers.fireAll()
	if c.closed.Load() {
		t.Fatal("closed while in use")
	}
	release2()
	// Released again: only the new timer closes it, the stale one not.
	f.timers.mu.Lock()
	stale := f.timers.all[0]
	f.timers.mu.Unlock()
	stale.f()
	if c.closed.Load() {
		t.Fatal("a stale idle timer closed the connection")
	}
	if f.timers.fire() != 1 || !c.closed.Load() {
		t.Fatal("not closed by its own idle timer")
	}
	if f.dec.asks.Load() != 1 {
		t.Fatalf("asks %d", f.dec.asks.Load())
	}
}

func TestDefaultIdleIsShort(t *testing.T) {
	if DefaultIdle <= 0 || DefaultIdle > 5*time.Minute {
		t.Fatalf("DefaultIdle %s", DefaultIdle)
	}
	f := newFixture(t, func(_ *fixture, c *Config[*conn]) { c.Idle = 0 })
	_, release, _ := f.pool.Acquire(context.Background(), req)
	release()
	f.timers.mu.Lock()
	defer f.timers.mu.Unlock()
	if f.timers.all[0].d != DefaultIdle {
		t.Fatalf("idle %s", f.timers.all[0].d)
	}
}

func TestRealTimerClosesIdle(t *testing.T) {
	f := newFixture(t, func(_ *fixture, c *Config[*conn]) { c.Idle, c.AfterFunc = 20*time.Millisecond, nil })
	c, release, err := f.pool.Acquire(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	release()
	deadline := time.Now().Add(2 * time.Second)
	for !c.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !c.closed.Load() || f.pool.Connected("crm-prod") {
		t.Fatal("not closed after the idle timeout")
	}
}

func TestDeniedAndRefusedDecisions(t *testing.T) {
	for _, c := range []struct {
		name   string
		prof   func(*Profile)
		decide func(*ticket.Ticket, *ticket.Decision)
		want   error
	}{
		{"denied", nil, func(_ *ticket.Ticket, d *ticket.Decision) {
			d.Decision, d.Secret, d.Reason, d.Rule = ticket.Denied, nil, "not now", &ticket.Rule{By: ticket.RuleHuman}
		}, ticket.ErrDenied},
		{"auto on never-auto", func(p *Profile) { p.NeverAuto = true }, nil, ticket.ErrAuto},
		{"no secret", nil, func(_ *ticket.Ticket, d *ticket.Decision) { d.Secret = nil }, ticket.ErrNoSecret},
		{"secret of another ticket", nil, func(tk *ticket.Ticket, d *ticket.Decision) {
			o := *tk
			o.ID = ticket.NewID(time.Now())
			d.Secret, _ = ticket.SealSecret(&o, []byte("x"))
		}, ticket.ErrOpen},
		{"dated before the ticket", nil, func(_ *ticket.Ticket, d *ticket.Decision) {
			d.At = time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
		}, ticket.ErrMismatch},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, nil)
			if c.prof != nil {
				c.prof(&f.prof)
			}
			f.dec.decide = c.decide
			_, _, err := f.pool.Acquire(context.Background(), req)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if c.want == ticket.ErrDenied && !strings.Contains(err.Error(), "not now") {
				t.Fatalf("denial without its reason: %v", err)
			}
			if f.dials.Load() != 0 || f.pool.Connected("crm-prod") {
				t.Fatal("connected without a usable approval")
			}
			// The next request asks again.
			f.dec.decide = nil
			f.prof.NeverAuto = false
			_, rel, err := f.pool.Acquire(context.Background(), req)
			if err != nil || f.dec.asks.Load() != 2 {
				t.Fatalf("ask again: %v", err)
			}
			rel()
		})
	}
}

func TestApprovalAged(t *testing.T) {
	now := time.Now()
	f := newFixture(t, func(_ *fixture, c *Config[*conn]) {
		c.MaxAge = time.Minute
		c.Now = func() time.Time { return now }
	})
	f.dec.decide = func(tk *ticket.Ticket, d *ticket.Decision) { now = now.Add(2 * time.Minute) }
	if _, _, err := f.pool.Acquire(context.Background(), req); !errors.Is(err, ticket.ErrExpired) {
		t.Fatalf("aged approval: %v", err)
	}
}

func TestNoSecretProfile(t *testing.T) {
	f := newFixture(t, nil)
	f.prof = Profile{Endpoint: "db:5432", Credential: ticket.CredentialKeychain, PolicyFP: policyFP, Production: true}
	c, rel, err := f.pool.Acquire(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	rel()
	tk := f.dec.last
	if c.secret != "" || tk.Subject.SecretTo != "" || tk.Risk != ticket.RiskProdWrite || !tk.Flags.Production ||
		len(tk.Screen.Warnings) != 1 || tk.Screen.Warnings[0] != "production" {
		t.Fatalf("ticket %+v", tk)
	}
	// A secret on a decision that asked for none is refused.
	f2 := newFixture(t, nil)
	f2.prof = f.prof
	f2.dec.decide = func(tk *ticket.Ticket, d *ticket.Decision) {
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		d.Secret, _ = ticket.Seal(k.PublicKey(), []byte("x"), nil)
	}
	if _, _, err := f2.pool.Acquire(context.Background(), req); !errors.Is(err, ticket.ErrNoSecret) {
		t.Fatalf("unasked secret: %v", err)
	}
}

func TestFailuresAskAgain(t *testing.T) {
	f := newFixture(t, nil)
	if _, _, err := f.pool.Acquire(context.Background(), Request{Profile: "missing"}); err == nil || f.dec.asks.Load() != 0 {
		t.Fatalf("missing profile: %v", err)
	}
	f.dialErr = errors.New("connection refused")
	if _, _, err := f.pool.Acquire(context.Background(), req); err == nil || f.pool.Connected("crm-prod") {
		t.Fatalf("dial error: %v", err)
	}
	f.dialErr = nil
	if _, rel, err := f.pool.Acquire(context.Background(), req); err != nil || f.dec.asks.Load() != 2 {
		t.Fatalf("after a dial error: %v", err)
	} else {
		rel()
	}
	got := f.kinds()
	if got[0] != EventFailed || got[1] != EventFailed || got[2] != EventConnected {
		t.Fatalf("events %v", got)
	}
}

func TestWaiterOutlivesCanceledAsker(t *testing.T) {
	f := newFixture(t, nil)
	f.dec.gate = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, _, err := f.pool.Acquire(ctx, req); first <- err }()
	for f.dec.asks.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	second := make(chan error, 1)
	go func() {
		_, rel, err := f.pool.Acquire(context.Background(), req)
		if rel != nil {
			rel()
		}
		second <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("first: %v", err)
	}
	close(f.dec.gate)
	if err := <-second; err != nil {
		t.Fatalf("second: %v", err)
	}
	if f.dec.asks.Load() != 2 {
		t.Fatalf("asks %d", f.dec.asks.Load())
	}
}

func TestClose(t *testing.T) {
	f := newFixture(t, nil)
	c, _, err := f.pool.Acquire(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.pool.Close(); err != nil || !c.closed.Load() {
		t.Fatalf("close: %v", err)
	}
	if _, _, err := f.pool.Acquire(context.Background(), req); !errors.Is(err, ErrClosed) {
		t.Fatalf("after close: %v", err)
	}
}

func TestNewChecksConfig(t *testing.T) {
	ok := Config[*conn]{Lock: "l", Asker: newDecider(t), Profile: func(string) (Profile, error) { return Profile{}, nil },
		Dial: func(context.Context, string, Grant) (*conn, error) { return nil, nil }}
	for name, mod := range map[string]func(*Config[*conn]){
		"lock": func(c *Config[*conn]) { c.Lock = "" }, "asker": func(c *Config[*conn]) { c.Asker = nil },
		"profile": func(c *Config[*conn]) { c.Profile = nil }, "dial": func(c *Config[*conn]) { c.Dial = nil },
	} {
		c := ok
		mod(&c)
		if _, err := New(c); err == nil {
			t.Errorf("no %s: accepted", name)
		}
	}
}

// A profile whose endpoint carries a DSN, a query or options is never
// asked for: nothing of it reaches the asker (ticket or screen), and the
// error does not echo it.
func TestSecretBearingEndpointNeverLeaves(t *testing.T) {
	for _, ep := range []string{"host=db password=hunter2", "db:5432/x?sslpassword=hunter2", "db;password=hunter2"} {
		f := newFixture(t, nil)
		f.prof.Endpoint = ep
		_, _, err := f.pool.Acquire(context.Background(), req)
		if !errors.Is(err, ticket.ErrInvalid) || f.dec.asks.Load() != 0 || f.dials.Load() != 0 {
			t.Fatalf("%q: err %v, asks %d, dials %d", ep, err, f.dec.asks.Load(), f.dials.Load())
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("%q: error echoes the endpoint: %v", ep, err)
		}
		if got := f.kinds(); len(got) != 1 || got[0] != EventFailed {
			t.Fatalf("%q: events %v", ep, got)
		}
	}
}
