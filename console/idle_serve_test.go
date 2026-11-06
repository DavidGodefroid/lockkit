//go:build unix

package console

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ipc"
)

// lockedClock is a clock shared by the test and the serving goroutine.
type lockedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *lockedClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *lockedClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// serveIdle serves h on a fresh socket and returns it with a channel closed
// when Serve returns.
func serveIdle(t *testing.T, h *harness) (string, <-chan struct{}) {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "lkidle")
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
	served := make(chan struct{})
	go func() { defer close(served); _ = h.s.Loop().Serve(ctx, ln, nil) }()
	t.Cleanup(func() { cancel(); <-served })
	return socket, served
}

// End to end over the socket: an agent polling status and hello every
// minute does not keep the console open; the request loop ends it on the
// idle timeout, as if nobody were there (#10).
func TestServeStatusPollingEndsOnIdleTimeout(t *testing.T) {
	clock := &lockedClock{t: time.Now()}
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Now = clock.now })
	socket, served := serveIdle(t, h)
	for i := 0; i < 19; i++ {
		clock.advance(time.Minute)
		method, params := ipc.MethodStatus, any(nil)
		if i%2 == 1 {
			method, params = ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor, Client: "lockmq"}
		}
		if r := dialAndCall(t, socket, method, params); r.Error != nil {
			t.Fatalf("%s at minute %d: %+v", method, i+1, r.Error)
		}
	}
	clock.advance(2 * time.Minute)
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("status polling kept the console open past the idle timeout")
	}
	if reason, ended := h.s.Ended(); !ended || reason != "idle timeout" {
		t.Fatalf("ended %v by %q", ended, reason)
	}
}

// Over the socket, a backend call is activity: the console stays open
// 19 minutes after it, polled by status meanwhile.
func TestServeBackendCallKeepsConsoleOpen(t *testing.T) {
	clock := &lockedClock{t: time.Now()}
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Now = clock.now; c.Approver = &fakeAsync{} })
	socket, served := serveIdle(t, h)
	clock.advance(15 * time.Minute)
	if r := dialAndCall(t, socket, "op.read", map[string]any{"queue": "orders"}); r.Error != nil {
		t.Fatalf("op.read: %+v", r.Error)
	}
	clock.advance(19 * time.Minute)
	if r := dialAndCall(t, socket, ipc.MethodStatus, nil); r.Error != nil {
		t.Fatalf("status: %+v", r.Error)
	}
	select { // at least one tick of the loop
	case <-served:
		reason, _ := h.s.Ended()
		t.Fatalf("ended by %q 19 minutes after a backend call", reason)
	case <-time.After(1500 * time.Millisecond):
	}
	clock.advance(2 * time.Minute)
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("not ended 21 minutes after the backend call")
	}
	if reason, _ := h.s.Ended(); reason != "idle timeout" {
		t.Fatalf("ended by %q", reason)
	}
}
