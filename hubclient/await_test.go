package hubclient_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// keepPolling keeps polling e's hub, as Watch does, until the test ends: the fake
// hub answers at once, so it polls every few milliseconds.
func keepPolling(t *testing.T, e *env) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			_, _ = e.client.Poll(ctx, 0)
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
}

// An auto rule decides the ticket as the hub accepts it: Await sees the
// decision well within DecisionWait, and the run goes ahead (Begin), never
// pending (#162).
func TestAwaitAutoDecisionWithinWindow(t *testing.T) {
	e := newEnv(t, nil)
	e.hub.AutoDecide("default:read")
	keepPolling(t, e)
	p, tk := e.plan(t, planHash)
	start := time.Now()
	id, err := e.client.Submit(context.Background(), e.store, p.ID, caller, tk, screen())
	if err != nil {
		t.Fatal(err)
	}
	if !e.client.Await(context.Background(), id, hubclient.DecisionWait) {
		t.Fatalf("no decision within %s", hubclient.DecisionWait)
	}
	if took := time.Since(start); took >= hubclient.DecisionWait {
		t.Fatalf("Await took %s", took)
	}
	run, d, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash))
	if err != nil || run == nil || !d.Auto() {
		t.Fatalf("begin: plan %v decision %+v err %v", run, d, err)
	}
}

// No decision within the window: Await answers false after it, and the
// request is pending (Begin: ErrPending). A decision taken later is kept
// all the same, for the agent's run of the ticket.
func TestAwaitNoDecisionThenLater(t *testing.T) {
	e := newEnv(t, nil)
	keepPolling(t, e)
	p, tk := e.plan(t, planHash)
	id, err := e.client.Submit(context.Background(), e.store, p.ID, caller, tk, screen())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if e.client.Await(context.Background(), id, 100*time.Millisecond) {
		t.Fatal("decided with no decision at the hub")
	}
	if took := time.Since(start); took < 100*time.Millisecond {
		t.Fatalf("Await gave up after %s", took)
	}
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, hubclient.ErrPending) {
		t.Fatalf("begin: %v, want ErrPending", err)
	}
	e.hub.DecideWith(id, ticket.Approved, "", nil, auto)
	if !e.client.Await(context.Background(), id, 5*time.Second) {
		t.Fatal("the later decision was not kept")
	}
	if run, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); err != nil || run == nil {
		t.Fatalf("begin after the decision: %v %v", run, err)
	}
}

// Await ends with its context, and never waits past MaxWait.
func TestAwaitEndsWithContext(t *testing.T) {
	e := newEnv(t, nil)
	p, tk := e.plan(t, planHash)
	id, err := e.client.Submit(context.Background(), e.store, p.ID, caller, tk, screen())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if e.client.Await(ctx, id, time.Hour) {
		t.Fatal("decided")
	}
	if ctx.Err() == nil {
		t.Fatal("Await returned before its context ended")
	}
}
