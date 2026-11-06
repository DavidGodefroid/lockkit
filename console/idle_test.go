//go:build unix

package console

import (
	"context"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ipc"
)

// idleHarness is a harness whose clock the test moves (uat: idle_timeout 20m).
func idleHarness(t *testing.T) (*harness, func(d time.Duration)) {
	t.Helper()
	now := time.Now()
	clock := now
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Now = func() time.Time { return clock } })
	return h, func(d time.Duration) { clock = clock.Add(d) }
}

func requireOpen(t *testing.T, h *harness, when string) {
	t.Helper()
	h.s.Tick()
	if reason, ended := h.s.Ended(); ended {
		t.Fatalf("%s: ended (%q)", when, reason)
	}
}

func requireIdle(t *testing.T, h *harness, when string) {
	t.Helper()
	h.s.Tick()
	if reason, ended := h.s.Ended(); !ended || reason != "idle timeout" {
		t.Fatalf("%s: ended %v %q, want idle timeout", when, ended, reason)
	}
}

// The console's own methods, polled by an agent, are not activity: the idle
// timeout still ends an unattended console (#10).
func TestIdleTimeoutIgnoresConsoleMethods(t *testing.T) {
	h, advance := idleHarness(t)
	calls := []struct {
		method string
		params any
	}{
		{ipc.MethodStatus, nil},
		{ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor, Client: "lockmq"}},
		{ipc.MethodChangeRequest, ipc.ChangeParams{Change: "allow orders"}},
		{ipc.MethodPIIList, nil},
		{"no.such.method", nil},
	}
	for i := 0; i < 19; i++ {
		advance(time.Minute)
		c := calls[i%len(calls)]
		h.call(t, context.Background(), c.method, c.params)
		requireOpen(t, h, "polling")
	}
	advance(time.Minute)
	requireIdle(t, h, "20 minutes of polling")
}

// A request that reaches the backend is activity, at its start and at its
// end: a long approval does not count against the idle time.
func TestIdleTimeoutCountsBackendCalls(t *testing.T) {
	h, advance := idleHarness(t)
	advance(15 * time.Minute)
	h.io.answers = []string{"y"}
	if r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "q"}); r.Error != nil {
		t.Fatal(r.Error)
	}
	advance(19 * time.Minute)
	requireOpen(t, h, "19 minutes after a backend call")

	// The human takes 10 minutes to answer: the idle time starts again at
	// the answer.
	h.io.answers = []string{"y"}
	h.io.onAsk = func() { advance(10 * time.Minute) }
	if r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "q"}); r.Error != nil {
		t.Fatal(r.Error)
	}
	h.io.onAsk = nil
	advance(19 * time.Minute)
	requireOpen(t, h, "19 minutes after a long approval")
	advance(time.Minute)
	requireIdle(t, h, "20 minutes after a long approval")
}

// The human's lines and keys are activity.
func TestIdleTimeoutCountsHumanInput(t *testing.T) {
	h, advance := idleHarness(t)
	advance(15 * time.Minute)
	h.s.Command(context.Background(), "")
	advance(15 * time.Minute)
	requireOpen(t, h, "15 minutes after a line")
	h.s.Key(KeyCtrlO)
	advance(19 * time.Minute)
	requireOpen(t, h, "19 minutes after a key")
	advance(time.Minute)
	requireIdle(t, h, "20 minutes after a key")
}
