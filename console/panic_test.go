//go:build unix

package console

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ipc"
)

// panicBackend is fakeBackend with a handler that panics.
type panicBackend struct{ fakeBackend }

func (b *panicBackend) Methods() map[string]Handler {
	m := b.fakeBackend.Methods()
	m["op.panic"] = func(context.Context, ipc.Request, Env) ipc.Response { panic("boom: secret-value-123") }
	return m
}

// A panicking handler answers its client an internal error, tells the
// console, audits the failure, and the session goes on.
func TestHandlerPanicRecovered(t *testing.T) {
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Backend = &panicBackend{fakeBackend{policy: uat()}} })
	r := h.call(t, context.Background(), "op.panic", nil)
	if r.Error == nil || r.Error.Code != ipc.CodeInternal || strings.Contains(r.Error.Message, "secret-value") {
		t.Fatalf("panic answer: %+v", r.Error)
	}
	if !strings.Contains(h.io.plain(), "op.panic") || !strings.Contains(h.io.plain(), "panicked") {
		t.Fatalf("the console was not told:\n%s", h.io.plain())
	}
	rec := h.lastRecord(t)
	if rec["event"] != "run" || rec["decision"] != "failed" || strings.Contains(rec["error"].(string), "secret-value") {
		t.Fatalf("record %v", rec)
	}
	h.io.answers = []string{"y"}
	if r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "q"}); r.Error != nil {
		t.Fatalf("the session did not go on: %+v", r.Error)
	}
}

// A panic answers on the response-time quantum like any request: its
// timing does not tell where the handler stopped.
func TestHandlerPanicLeveled(t *testing.T) {
	const q = 300 * time.Millisecond
	h := newHarness(t, uat(), func(c *ServerConfig) {
		c.Backend = &panicBackend{fakeBackend{policy: uat()}}
		c.Quantum = q
	})
	start := time.Now()
	if r := h.call(t, context.Background(), "op.panic", nil); r.Error == nil {
		t.Fatal("no error")
	}
	if el := time.Since(start); el < q {
		t.Fatalf("panic answered after %s, before the %s quantum", el, q)
	}
}

// The loop itself survives a panicking Handle: the client gets an internal
// error, another client is served, and Serve returns when its context ends.
func TestLoopSurvivesPanicAndStops(t *testing.T) {
	d, err := os.MkdirTemp("/tmp", "lkpanic")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	socket := filepath.Join(d, "s")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	io := &fakeIO{}
	l := &Loop{IO: io, Ended: func() bool { return false }, Handle: func(_ context.Context, req ipc.Request) ipc.Response {
		if req.Method == "op.panic" {
			panic("boom")
		}
		return OKResp(req.ID, "ok")
	}}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- l.Serve(ctx, ln, nil) }()
	if r := dialAndCall(t, socket, "op.panic", nil); r.Error == nil || r.Error.Code != ipc.CodeInternal {
		t.Fatalf("panic answer: %+v %s", r.Error, r.Result)
	}
	if r := dialAndCall(t, socket, "op.ok", nil); r.Error != nil {
		t.Fatalf("next client: %+v", r.Error)
	}
	cancel()
	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}
