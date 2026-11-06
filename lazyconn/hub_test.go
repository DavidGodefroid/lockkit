package lazyconn_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/lazyconn"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// The whole path: lock pool -> hub client -> (fake) lockhub -> the
// decider (`lox run`'s side: it verifies the ticket under the lock key and
// seals the secret) -> signed decision -> hub -> lock -> backend.

const inst = "crm-prod"

var policyFP = "sha256:" + strings.Repeat("2", 64)

type backend struct {
	secret string
	closed atomic.Bool
}

func (b *backend) Close() error { b.closed.Store(true); return nil }

type world struct {
	hub     *hubtest.Hub
	client  *hubclient.Client
	pool    *lazyconn.Pool[*backend]
	lockPub ed25519.PublicKey
	idle    chan func() // idle closes, fired by the test
	secret  []byte
	mu      sync.Mutex
	decided map[string]bool
	deny    bool
}

func newWorld(t *testing.T) *world {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := hubtest.New(t, inst, pub)
	c, err := hubclient.New(hubclient.Config{URL: h.URL(), Instance: inst, Key: priv, HubKey: h.Pub,
		StateFile: filepath.Join(t.TempDir(), "hub-state.json")})
	if err != nil {
		t.Fatal(err)
	}
	w := &world{hub: h, client: c, lockPub: pub, idle: make(chan func(), 8), secret: []byte("correct horse battery"),
		decided: map[string]bool{}}
	p, err := lazyconn.New(lazyconn.Config[*backend]{
		Lock:  "locksql",
		Asker: c,
		Profile: func(string) (lazyconn.Profile, error) {
			return lazyconn.Profile{Endpoint: "db.internal:5432/shop", Credential: ticket.CredentialAsk, NeedSecret: true,
				PolicyFP: policyFP, Production: true}, nil
		},
		Dial: func(_ context.Context, _ string, g lazyconn.Grant) (*backend, error) {
			return &backend{secret: string(g.Secret)}, nil
		},
		AfterFunc: func(_ time.Duration, f func()) lazyconn.Timer { w.idle <- f; return stopper{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	w.pool = p
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go w.decide(t, ctx)
	return w
}

type stopper struct{}

func (stopper) Stop() bool { return true }

// decide answers each new ticket at the hub as `lox run` would.
func (w *world) decide(t *testing.T, ctx context.Context) {
	for ctx.Err() == nil {
		for _, id := range w.hub.Tickets() {
			w.mu.Lock()
			done := w.decided[id]
			w.decided[id] = true
			deny := w.deny
			w.mu.Unlock()
			if done {
				continue
			}
			tk, err := ticket.VerifyTicket(w.lockPub, w.hub.Ticket(id))
			if err != nil {
				t.Errorf("decider: %v", err)
				return
			}
			if deny {
				w.hub.DecideWith(id, ticket.Denied, "no connections tonight", nil, nil)
				continue
			}
			box, err := ticket.SealSecret(tk, w.secret)
			if err != nil {
				t.Errorf("decider: %v", err)
				return
			}
			w.hub.DecideWith(id, ticket.Approved, "", nil, func(d *ticket.Decision) {
				d.Rule, d.Facade, d.Secret = &ticket.Rule{By: ticket.RuleAuto, ID: "crm-connect"}, "lox-run", box
			})
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (w *world) acquire(t *testing.T) (*backend, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	b, rel, err := w.pool.Acquire(ctx, lazyconn.Request{Profile: "crm-prod", Requester: ticket.Requester{Agent: "dev-1"}})
	if err != nil {
		t.Fatal(err)
	}
	return b, rel
}

func TestConnectThroughTheHub(t *testing.T) {
	w := newWorld(t)
	if len(w.hub.Tickets()) != 0 {
		t.Fatal("a ticket before any request")
	}
	b, rel := w.acquire(t)
	if b.secret != string(w.secret) {
		t.Fatalf("the backend got %q", b.secret)
	}
	ids := w.hub.Tickets()
	if len(ids) != 1 || !w.hub.Consumed(ids[0]) {
		t.Fatalf("tickets %v", ids)
	}
	// The hub saw the ticket and the decision; neither has the secret in
	// clear.
	seen := append([][]byte{w.hub.Ticket(ids[0])}, w.hub.Decisions()...)
	for _, raw := range seen {
		if bytes.Contains(raw, w.secret) {
			t.Fatalf("the hub saw the secret: %s", raw)
		}
	}
	tk, err := ticket.VerifyTicket(w.lockPub, w.hub.Ticket(ids[0]))
	if err != nil || tk.Kind != ticket.KindConnect || tk.Subject.SecretTo == "" || !tk.Flags.Production {
		t.Fatalf("ticket at the hub: %v %+v", err, tk)
	}
	// Shared while open.
	b2, rel2 := w.acquire(t)
	if b2 != b || len(w.hub.Tickets()) != 1 {
		t.Fatal("a second ticket while connected")
	}
	rel2()
	rel()
	// Idle: closed; the next request asks the hub again.
	(<-w.idle)()
	if !b.closed.Load() || w.pool.Connected("crm-prod") {
		t.Fatal("not closed when idle")
	}
	b3, rel3 := w.acquire(t)
	defer rel3()
	if b3 == b || len(w.hub.Tickets()) != 2 {
		t.Fatalf("re-ask after close: %d tickets", len(w.hub.Tickets()))
	}
}

func TestConnectDeniedThroughTheHub(t *testing.T) {
	w := newWorld(t)
	w.deny = true
	_, _, err := w.pool.Acquire(context.Background(), lazyconn.Request{Profile: "crm-prod"})
	if !errors.Is(err, ticket.ErrDenied) || !strings.Contains(err.Error(), "no connections tonight") {
		t.Fatalf("denied: %v", err)
	}
	if w.pool.Connected("crm-prod") {
		t.Fatal("connected on a denial")
	}
}

// With the lock's Watch polling at the same time, Ask gets its decision
// from the shared inbox.
func TestConnectWhileWatching(t *testing.T) {
	w := newWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := plans.Open(filepath.Join(t.TempDir(), "plans"))
	if err != nil {
		t.Fatal(err)
	}
	go w.client.Watch(ctx, st, nil)
	time.Sleep(20 * time.Millisecond)
	b, rel := w.acquire(t)
	defer rel()
	if b.secret != string(w.secret) {
		t.Fatal("no secret")
	}
	if slices.Contains(w.hub.Sinces(), "") {
		t.Fatal("a poll without a cursor")
	}
}
