package plans

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

var lockKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))

// tkt is the signed ticket of plan p, fixed id tk1.
func tkt(t *testing.T, p *Plan, expires *time.Time) *ticket.Ticket {
	t.Helper()
	k := ticket.NewTicket(ticket.Source{Lock: "locksql", Instance: "crm-prod"}, ticket.RiskWrite,
		p.Binding.PlanHash, p.Binding.PolicyFP, p.Created, 0)
	k.ID = tk1
	if expires != nil {
		e := *expires
		k.Expires = &e
	}
	if err := k.Sign(lockKey); err != nil {
		t.Fatal(err)
	}
	return k
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

const (
	hashA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	fpA   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	fpB   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	tk1   = "01JBDN0Z0000000000000000AB"
)

var (
	agent3 = Caller{UID: 1000, Token: "token-of-dev-3"}
	agent4 = Caller{UID: 1000, Token: "token-of-dev-4"}
	other  = Caller{UID: 1001, Token: "token-of-dev-3"}
)

func bind(c Caller) Binding {
	return Binding{UID: c.UID, Agent: "dev-3", TokenHash: HashToken(c.Token), PolicyFP: fpA, PlanHash: hashA}
}

func newStore(t *testing.T) (*Store, string, *clock) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "plans")
	c := &clock{t: time.Date(2026, 10, 29, 22, 0, 0, 0, time.UTC)}
	s, err := Open(dir, WithClock(c.now))
	if err != nil {
		t.Fatal(err)
	}
	return s, dir, c
}

func TestLifecycle(t *testing.T) {
	s, _, _ := newStore(t)
	p, err := s.Create(bind(agent3), json.RawMessage(`{"sql":"UPDATE t SET a = 1"}`), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if p.State != Planned {
		t.Fatal(p.State)
	}
	if err := s.Check(p.ID, agent3, fpA, hashA); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkPending(p.ID, agent3, tkt(t, p, nil)); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.FindPending(agent3, hashA); !ok || got.ID != p.ID || got.Ticket != tk1 {
		t.Fatalf("FindPending: %v %v", got, ok)
	}
	if got, err := s.ByTicket(tk1, agent3); err != nil || got.ID != p.ID {
		t.Fatalf("ByTicket: %v %v", got, err)
	} else if lt, err := got.LockTicket(lockKey.Public().(ed25519.PublicKey)); err != nil || lt.ID != tk1 || lt.PlanHash != hashA {
		t.Fatalf("LockTicket: %v %v", lt, err)
	}
	if err := s.Begin(p.ID, agent3, "nonce-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(p.ID, agent3, true, ""); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(p.ID, agent3)
	if got.State != Executed || got.Nonce != "nonce-1" {
		t.Fatalf("%+v", got)
	}
}

func TestBindingMismatch(t *testing.T) {
	s, _, _ := newStore(t)
	p, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
	if _, err := s.Get(p.ID, other); !errors.Is(err, ErrWrongPeer) {
		t.Errorf("other uid: %v", err)
	}
	if _, err := s.Get(p.ID, agent4); !errors.Is(err, ErrWrongRequester) {
		t.Errorf("other agent: %v", err)
	}
	if _, err := s.Get(p.ID, Caller{UID: 1000}); !errors.Is(err, ErrWrongRequester) {
		t.Errorf("no token: %v", err)
	}
	if err := s.Begin(p.ID, agent4, "n"); !errors.Is(err, ErrWrongRequester) {
		t.Errorf("begin by other agent: %v", err)
	}
	if _, err := s.Get("01JBDN0Z0000000000000000ZZ", agent3); !errors.Is(err, ErrNoSuchPlan) {
		t.Errorf("unknown: %v", err)
	}
	if _, ok := s.FindPending(agent3, hashA); ok {
		t.Error("planned is not pending")
	}
	_ = s.MarkPending(p.ID, agent3, tkt(t, p, nil))
	if _, ok := s.FindPending(agent4, hashA); ok {
		t.Error("dedup crossed agents")
	}
	if _, ok := s.FindPending(agent3, hashB); ok {
		t.Error("dedup crossed plan hashes")
	}
	if _, err := s.ByTicket(tk1, agent4); !errors.Is(err, ErrWrongRequester) {
		t.Errorf("ByTicket other agent: %v", err)
	}
	// A plan without a token is bound to having none.
	q, _ := s.Create(Binding{UID: 1000, PolicyFP: fpA, PlanHash: hashA}, json.RawMessage(`{}`), 0)
	if _, err := s.Get(q.ID, agent3); !errors.Is(err, ErrWrongRequester) {
		t.Errorf("token on a tokenless plan: %v", err)
	}
	if _, err := s.Get(q.ID, Caller{UID: 1000}); err != nil {
		t.Error(err)
	}
}

func TestStale(t *testing.T) {
	for _, c := range []struct{ fp, hash string }{{fpB, hashA}, {fpA, hashB}, {fpB, hashB}} {
		s, _, _ := newStore(t)
		p, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
		_ = s.MarkPending(p.ID, agent3, tkt(t, p, nil))
		if err := s.Check(p.ID, agent3, c.fp, c.hash); !errors.Is(err, ErrStale) {
			t.Fatalf("%v: %v", c, err)
		}
		got, _ := s.Get(p.ID, agent3)
		if got.State != Stale {
			t.Fatalf("state %s", got.State)
		}
		if err := s.Begin(p.ID, agent3, "n"); !errors.Is(err, ErrUsed) {
			t.Fatalf("stale plan began: %v", err)
		}
	}
}

func TestSingleUse(t *testing.T) {
	s, _, _ := newStore(t)
	p, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
	if err := s.Begin(p.ID, agent3, "nonce-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Begin(p.ID, agent3, "nonce-2"); !errors.Is(err, ErrUsed) {
		t.Fatalf("second begin: %v", err)
	}
	_ = s.Finish(p.ID, agent3, false, "connection lost")
	if err := s.Begin(p.ID, agent3, "nonce-3"); !errors.Is(err, ErrUsed) {
		t.Fatalf("begin after failure: %v", err)
	}
	// The nonce of one plan does not begin another.
	q, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
	if err := s.Begin(q.ID, agent3, "nonce-1"); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed nonce: %v", err)
	}
	if err := s.End(q.ID, agent3, Executed, ""); !errors.Is(err, ErrState) {
		t.Fatalf("End to executed: %v", err)
	}
	if err := s.End(q.ID, agent3, Denied, "no"); err != nil {
		t.Fatal(err)
	}
	if err := s.Begin(q.ID, agent3, "nonce-9"); !errors.Is(err, ErrUsed) {
		t.Fatalf("denied plan began: %v", err)
	}
	if err := s.MarkPending(q.ID, agent3, tkt(t, q, nil)); !errors.Is(err, ErrState) {
		t.Fatalf("denied → pending: %v", err)
	}
}

// Concurrent begins of one plan: exactly one wins.
func TestSingleUseConcurrent(t *testing.T) {
	s, _, _ := newStore(t)
	p, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Begin(p.ID, agent3, "nonce-"+string(rune('a'+i))) == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d begins won", wins)
	}
}

func TestRestart(t *testing.T) {
	s, dir, c := newStore(t)
	p, _ := s.Create(bind(agent3), json.RawMessage(`{"sql":"DELETE FROM t WHERE id = 1"}`), 0)
	_ = s.MarkPending(p.ID, agent3, tkt(t, p, nil))
	q, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
	_ = s.Begin(q.ID, agent3, "nonce-q")
	r, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
	_ = s.Begin(r.ID, agent3, "nonce-r")
	_ = s.Finish(r.ID, agent3, true, "")
	// An interrupted write leaves a temp file behind.
	if err := os.WriteFile(filepath.Join(dir, "."+p.ID+".json.123.tmp"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir, WithClock(c.now))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.Get(p.ID, agent3)
	if err != nil || got.State != Pending || got.Ticket != tk1 || string(got.Body) != `{"sql":"DELETE FROM t WHERE id = 1"}` {
		t.Fatalf("pending plan after restart: %+v %v", got, err)
	}
	if got, _ := s2.Get(q.ID, agent3); got.State != Failed {
		t.Fatalf("executing plan after restart: %s", got.State)
	}
	if got, _ := s2.Get(r.ID, agent3); got.State != Executed {
		t.Fatalf("executed plan after restart: %s", got.State)
	}
	// Nonces survive the restart.
	n, _ := s2.Create(bind(agent3), json.RawMessage(`{}`), 0)
	if err := s2.Begin(n.ID, agent3, "nonce-r"); !errors.Is(err, ErrReplay) {
		t.Fatalf("nonce replayed after restart: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "."+p.ID+".json.123.tmp")); !os.IsNotExist(err) {
		t.Error("temp file kept")
	}
	if err := s2.Begin(p.ID, agent3, "nonce-p"); err != nil {
		t.Fatal(err)
	}
}

func TestExpiryAndPrune(t *testing.T) {
	s, dir, c := newStore(t)
	p, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 10*time.Minute)
	keep, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
	exp := c.now().Add(4 * time.Hour)
	pend, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 10*time.Minute)
	_ = s.MarkPending(pend.ID, agent3, tkt(t, pend, &exp)) // the ticket's TTL replaces the plan's
	c.add(11 * time.Minute)
	if _, err := s.Get(p.ID, agent3); !errors.Is(err, ErrNoSuchPlan) {
		t.Fatalf("expired plan: %v", err)
	}
	if _, err := s.Get(pend.ID, agent3); err != nil {
		t.Fatalf("pending plan expired with the plan TTL: %v", err)
	}
	c.add(4 * time.Hour)
	if _, ok := s.FindPending(agent3, hashA); ok {
		t.Fatal("expired pending plan found")
	}
	if _, err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(keep.ID, agent3); err != nil {
		t.Fatal("plan without TTL expired")
	}
	c.add(Retention)
	n, err := s.Prune()
	if err != nil || n != 2 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, p.ID+".json")); !os.IsNotExist(err) {
		t.Error("pruned file kept")
	}
	if _, err := s.Get(keep.ID, agent3); err != nil {
		t.Fatal("live plan pruned")
	}
}

func TestWithdrawAll(t *testing.T) {
	s, _, _ := newStore(t)
	p, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
	_ = s.MarkPending(p.ID, agent3, tkt(t, p, nil))
	q, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
	w, err := s.WithdrawAll("started without the hub")
	if err != nil || len(w) != 1 || w[0].ID != p.ID || w[0].State != Withdrawn {
		t.Fatalf("%v %v", w, err)
	}
	if got, _ := s.Get(q.ID, agent3); got.State != Planned {
		t.Fatal("planned plan withdrawn")
	}
	if len(s.Pending()) != 0 {
		t.Fatal("still pending")
	}
}

func TestPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits")
	}
	s, dir, c := newStore(t)
	p, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
	_ = s.Begin(p.ID, agent3, "nonce-1")
	s.Close() // the Opens below check the files, not the lock
	for _, path := range []string{dir, filepath.Join(dir, p.ID+".json"), filepath.Join(dir, "nonces")} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o600)
		if fi.IsDir() {
			want = 0o700
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: %v, want %v", path, fi.Mode().Perm(), want)
		}
	}
	for _, path := range []string{filepath.Join(dir, p.ID+".json"), filepath.Join(dir, "nonces"), dir} {
		mode := os.FileMode(0o640)
		if path == dir {
			mode = 0o750
		}
		_ = os.Chmod(path, mode)
		if _, err := Open(dir, WithClock(c.now)); !errors.Is(err, ErrUnsafe) {
			t.Errorf("%s at %v: %v", path, mode, err)
		}
		if path == dir {
			_ = os.Chmod(path, 0o700)
		} else {
			_ = os.Chmod(path, 0o600)
		}
	}
	// A symlinked plan file is refused.
	link := filepath.Join(dir, "01JBDN0Z0000000000000000AC.json")
	if err := os.Symlink(filepath.Join(dir, p.ID+".json"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, WithClock(c.now)); !errors.Is(err, ErrUnsafe) {
		t.Errorf("symlink: %v", err)
	}
}

func TestLimitsAndTokens(t *testing.T) {
	s, dir, _ := newStore(t)
	if _, err := s.Create(bind(agent3), make(json.RawMessage, MaxBody+1), 0); err == nil {
		t.Error("big body accepted")
	}
	if _, err := s.Create(bind(agent3), json.RawMessage(`{`), 0); err == nil {
		t.Error("invalid body accepted")
	}
	p, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
	b, _ := os.ReadFile(filepath.Join(dir, p.ID+".json"))
	if strings.Contains(string(b), agent3.Token) {
		t.Fatal("token written in clear")
	}
	if err := s.MarkPending(p.ID, agent3, &ticket.Ticket{ID: "x"}); err == nil {
		t.Error("unsigned ticket accepted")
	}
	other := tkt(t, p, nil)
	other.PlanHash = hashB
	_ = other.Sign(lockKey)
	if err := s.MarkPending(p.ID, agent3, other); !errors.Is(err, ErrStale) {
		t.Errorf("ticket for another plan hash: %v", err)
	}
	if HashToken("") != "" || HashToken("a") == HashToken("b") {
		t.Error("HashToken")
	}
}

// One store per directory: a second Open while the first is open fails
// (two consoles on one volume would each accept the same decision nonce),
// and succeeds once it is closed (#60).
func TestOpenLocksTheDirectory(t *testing.T) {
	s, dir, c := newStore(t)
	if _, err := Open(dir, WithClock(c.now)); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open: %v, want ErrLocked", err)
	}
	p, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
	if err := s.Begin(p.ID, agent3, "nonce-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	s2, err := Open(dir, WithClock(c.now))
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	defer s2.Close()
	q, _ := s2.Create(bind(agent3), json.RawMessage(`{}`), 0)
	if err := s2.Begin(q.ID, agent3, "nonce-1"); !errors.Is(err, ErrReplay) {
		t.Fatalf("nonce reused across stores: %v", err)
	}
}

func TestWithdrawAllUntoldUntilTold(t *testing.T) {
	s, dir, clock := newStore(t)
	p, _ := s.Create(bind(agent3), json.RawMessage(`{}`), 0)
	if err := s.MarkPending(p.ID, agent3, tkt(t, p, nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WithdrawAll("started without the hub"); err != nil {
		t.Fatal(err)
	}
	// Survives a restart, and Prune keeps it past the retention.
	_ = s.Close()
	s2, err := Open(dir, WithClock(clock.now))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	u := s2.Untold()
	if len(u) != 1 || u[0].ID != p.ID || u[0].State != Withdrawn || u[0].Reason != "started without the hub" {
		t.Fatalf("untold %+v", u)
	}
	clock.add(Retention + time.Hour)
	if n, err := s2.Prune(); err != nil || n != 0 {
		t.Fatalf("pruned an untold plan: %d %v", n, err)
	}
	if err := s2.MarkTold(p.ID); err != nil {
		t.Fatal(err)
	}
	if len(s2.Untold()) != 0 {
		t.Fatal("still untold")
	}
	if n, err := s2.Prune(); err != nil || n != 1 {
		t.Fatalf("told plan not pruned: %d %v", n, err)
	}
	if err := s2.MarkTold(p.ID); !errors.Is(err, ErrNoSuchPlan) {
		t.Fatalf("MarkTold of a pruned plan: %v", err)
	}
}
