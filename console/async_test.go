//go:build unix

package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeAsync is an AsyncApprover: it numbers the tickets and keeps the
// decisions it was handed.
type fakeAsync struct {
	mu        sync.Mutex
	decisions []Decision
	err       error
	noTicket  bool
	withdrawn []string
}

// Withdraw records the tickets withdrawn.
func (a *fakeAsync) Withdraw(_ context.Context, d Decision, ticket, reason string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.withdrawn = append(a.withdrawn, ticket)
	return nil
}

func (a *fakeAsync) Mode() string { return "hub" }

// Approve takes the console's own decisions only.
func (a *fakeAsync) Approve(_ context.Context, d Decision) Result {
	if d.Screen != nil {
		panic("a request asked on the terminal")
	}
	return Result{Outcome: Unanswered}
}

func (a *fakeAsync) Submit(_ context.Context, d Decision) (Pending, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.decisions = append(a.decisions, d)
	if a.noTicket {
		return Pending{}, a.err
	}
	return Pending{Ticket: fmt.Sprintf("T%d", len(a.decisions))}, a.err
}

func pendingOf(t *testing.T, raw json.RawMessage) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("result %s: %v", raw, err)
	}
	return m
}

// An asynchronous approver gets the screen; the request is answered
// pending, a result and not an error, with no prompt and no bell.
func TestAsyncApproverPending(t *testing.T) {
	a := &fakeAsync{}
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Approver = a })
	r := h.call(t, context.Background(), "op.read", map[string]any{"queue": "orders", "note": "why"})
	if r.Error != nil {
		t.Fatalf("error %+v", r.Error)
	}
	if m := pendingOf(t, r.Result); m["status"] != "pending" || m["ticket"] != "T1" || m["lock"] != testProduct.Name {
		t.Fatalf("result %v", m)
	}
	if len(a.decisions) != 1 || a.decisions[0].Screen == nil || a.decisions[0].Screen.Body[0] != "READ orders" || a.decisions[0].Screen.Note != "why" {
		t.Fatalf("decisions %+v", a.decisions)
	}
	if h.io.promptCount() != 0 || h.io.bells != 0 {
		t.Fatalf("prompted: %v, bells %d", h.io.promptList(), h.io.bells)
	}
	if !containsLine(h.io, "pending: ticket T1") {
		t.Fatalf("no pending line:\n%s", h.io.plain())
	}
}

// A hub that refuses the ticket or cannot be reached leaves the request
// pending, never asked on the terminal instead; with no ticket at all the
// request fails.
func TestAsyncApproverFailClosed(t *testing.T) {
	a := &fakeAsync{err: errors.New("hub unreachable")}
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Approver = a })
	h.io.answers = []string{"y"}
	r := h.call(t, context.Background(), "op.read", map[string]any{"queue": "orders"})
	if r.Error != nil || pendingOf(t, r.Result)["ticket"] != "T1" || h.io.promptCount() != 0 {
		t.Fatalf("result %s error %+v prompts %v", r.Result, r.Error, h.io.promptList())
	}
	if !containsLine(h.io, "not delivered yet: hub unreachable") {
		t.Fatalf("no delivery warning:\n%s", h.io.plain())
	}
	a.noTicket = true
	r = h.call(t, context.Background(), "op.read", map[string]any{"queue": "orders"})
	if r.Error == nil || r.Result != nil || h.io.promptCount() != 0 {
		t.Fatalf("no ticket: result %s error %+v prompts %v", r.Result, r.Error, h.io.promptList())
	}
}

// Concurrent clients each get their own ticket: no request waits for a
// human behind another one.
func TestAsyncApproverConcurrentRequests(t *testing.T) {
	a := &fakeAsync{}
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Approver = a })
	d, err := os.MkdirTemp("/tmp", "lkasync")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	socket := filepath.Join(d, "s")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- h.s.Loop().Serve(ctx, ln, nil) }()
	const n = 8
	tickets := make(chan string, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := dialAndCall(t, socket, "op.read", map[string]any{"queue": "orders"})
			if r.Error != nil {
				t.Errorf("error %+v", r.Error)
				return
			}
			tickets <- pendingOf(t, r.Result)["ticket"]
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent requests did not all get an answer")
	}
	cancel()
	<-served
	close(tickets)
	seen := map[string]bool{}
	for tk := range tickets {
		seen[tk] = true
	}
	if len(seen) != n {
		t.Fatalf("tickets %v", seen)
	}
}

// The console's auto mode never bypasses the hub.
func TestAsyncApproverNoLocalAutoMode(t *testing.T) {
	a := &fakeAsync{}
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Approver = a; c.Auto = true })
	r := h.call(t, context.Background(), "op.read", map[string]any{"queue": "orders"})
	if r.Error != nil || pendingOf(t, r.Result)["status"] != "pending" || len(a.decisions) != 1 || h.s.Auto() {
		t.Fatalf("result %s decisions %d auto %v", r.Result, len(a.decisions), h.s.Auto())
	}
}

// A pending request is audited with its ticket; one that cannot be
// audited is withdrawn and refused, never answered pending.
func TestAsyncApproverPendingAudited(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes a read-only file")
	}
	a := &fakeAsync{}
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Approver = a })
	r := h.call(t, context.Background(), "op.read", map[string]any{"queue": "orders"})
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	rec := h.lastRecord(t)
	if rec["event"] != "pending" || rec["decision"] != "pending" || rec["ticket"] != "T1" || rec["approval"] != "hub" {
		t.Fatalf("record %v", rec)
	}
	if err := os.Chmod(h.log, 0o400); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(h.log, 0o600)
	r = h.call(t, context.Background(), "op.read", map[string]any{"queue": "orders"})
	if r.Error == nil || r.Error.Code != -32603 || r.Result != nil {
		t.Fatalf("unrecorded pending: %s %+v", r.Result, r.Error)
	}
	if len(a.withdrawn) != 1 || a.withdrawn[0] != "T2" {
		t.Fatalf("withdrawn %v", a.withdrawn)
	}
}
