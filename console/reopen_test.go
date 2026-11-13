//go:build unix

package console

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/ipc"
)

// refusedHarness is a harness whose files hold a loosening (tier peek)
// the human refused at :review.
func refusedHarness(t *testing.T) (*harness, fakePolicy) {
	t.Helper()
	h := newHarness(t, uat(), nil)
	looser := uat()
	looser.Tier = "peek"
	h.b.policy = looser
	h.s.CheckPolicy()
	h.io.answers = []string{"n"}
	h.s.Command(context.Background(), ":review")
	if !strings.Contains(h.io.plain(), "policy change refused") || !h.s.PolicyRefused() || h.s.PolicyPending() {
		t.Fatalf("refusal:\n%s", h.io.plain())
	}
	return h, looser
}

// A refused loosening stays refused, polls included, until the human
// re-opens it: it is then pending again, its diff shown by :review (#158).
func TestReopenRefusedPending(t *testing.T) {
	h, _ := refusedHarness(t)
	h.s.CheckPolicy()
	if h.s.PolicyPending() || !h.s.PolicyRefused() {
		t.Fatal("a poll offered the refused change again")
	}
	h.s.Command(context.Background(), ":review")
	if !strings.Contains(h.io.plain(), ":reopen to review it again") {
		t.Fatalf(":review does not point at :reopen:\n%s", h.io.plain())
	}
	h.s.Command(context.Background(), ":reopen")
	if !h.s.PolicyPending() || h.s.PolicyRefused() {
		t.Fatalf("not pending after :reopen:\n%s", h.io.plain())
	}
	if !strings.Contains(h.io.statusLine(), "policy change pending") {
		t.Fatalf("status line %q", h.io.statusLine())
	}
	if rec := h.lastRecord(t); rec["event"] != "policy" || rec["decision"] != "reopened" {
		t.Fatalf("audit %v", rec)
	}
	// Refused again: it stays refused, and can be re-opened again.
	h.io.answers = []string{"n"}
	h.s.Command(context.Background(), ":review")
	if h.s.PolicyPending() || !h.s.PolicyRefused() || h.s.Policy().(fakePolicy).Tier != "read" {
		t.Fatal("second refusal")
	}
	h.s.Command(context.Background(), ":reopen")
	if !h.s.PolicyPending() {
		t.Fatal("not pending after the second :reopen")
	}
}

// Approving a re-opened loosening applies it exactly as a first approval
// would: the same policy in force, saved, audited applied.
func TestReopenApproveAsFirstApproval(t *testing.T) {
	first := newHarness(t, uat(), nil)
	looser := uat()
	looser.Tier = "peek"
	first.b.policy = looser
	first.s.CheckPolicy()
	first.io.answers = []string{"y"}
	first.s.Command(context.Background(), ":review")

	h, _ := refusedHarness(t)
	h.s.Command(context.Background(), ":reopen")
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	if !strings.Contains(h.io.plain(), "policy change applied") {
		t.Fatalf("not applied:\n%s", h.io.plain())
	}
	for _, x := range []*harness{first, h} {
		if !reflect.DeepEqual(x.s.Policy(), Policy(looser)) || x.s.PolicyPending() || x.s.PolicyRefused() {
			t.Fatalf("in force %+v", x.s.Policy())
		}
		var saved fakePolicy
		if ok, err := config.LoadApproved(testProduct, x.state, "user-uat", &saved); !ok || err != nil || !reflect.DeepEqual(saved, looser) {
			t.Fatalf("saved %v %v %+v", ok, err, saved)
		}
		if rec := x.lastRecord(t); rec["event"] != "policy" || rec["decision"] != "applied" || rec["approval"] != first.lastRecord(t)["approval"] {
			t.Fatalf("audit %v", rec)
		}
	}
}

// A loosening refused at start (ServerConfig.Refused) re-opens the same
// way; with nothing refused, or the files gone back to the approved
// policy, :reopen has nothing to offer.
func TestReopenRefusedAtStart(t *testing.T) {
	looser := uat()
	looser.Tier = "peek"
	h := newHarness(t, uat(), func(c *ServerConfig) {
		c.Backend.(*fakeBackend).policy = looser
		c.Refused = config.Fingerprint(looser)
	})
	h.s.CheckPolicy()
	if h.s.PolicyPending() {
		t.Fatal("the change refused at start is pending")
	}
	h.s.Command(context.Background(), ":reopen")
	if !h.s.PolicyPending() {
		t.Fatalf("not pending:\n%s", h.io.plain())
	}

	n := newHarness(t, uat(), nil)
	n.s.Command(context.Background(), ":reopen")
	if n.s.PolicyPending() || !strings.Contains(n.io.plain(), "no refused policy change to re-open") {
		t.Fatalf("nothing refused:\n%s", n.io.plain())
	}
	g, _ := refusedHarness(t)
	g.b.policy = uat()
	g.s.Command(context.Background(), ":reopen")
	if g.s.PolicyPending() || g.s.PolicyRefused() || !strings.Contains(g.io.plain(), "no refused policy change to re-open") {
		t.Fatalf("files back to the approved policy:\n%s", g.io.plain())
	}
}

// Unreadable files keep the refusal: :reopen offers nothing it cannot
// show.
func TestReopenLoadErrorKeepsRefusal(t *testing.T) {
	h, _ := refusedHarness(t)
	h.b.loadErr = os.ErrPermission
	h.s.Command(context.Background(), ":reopen")
	if h.s.PolicyPending() || !h.s.PolicyRefused() {
		t.Fatal("refusal lost on a load error")
	}
}

// Only the human re-opens a refused change: no client method does, a
// change request included, and an unknown method named after it is
// refused.
func TestReopenNotByAgent(t *testing.T) {
	h, _ := refusedHarness(t)
	for _, m := range []string{"reopen", "policy.reopen", ":reopen", "review"} {
		if r := h.call(t, context.Background(), m, map[string]any{}); r.Error == nil {
			t.Fatalf("method %q answered %s", m, r.Result)
		}
	}
	if r := h.call(t, context.Background(), ipc.MethodChangeRequest, ipc.ChangeParams{Change: ":reopen"}); r.Error != nil {
		t.Fatalf("change.request %+v", r.Error)
	}
	h.s.CheckPolicy()
	if h.s.PolicyPending() || !h.s.PolicyRefused() {
		t.Fatal("a client re-opened the refused change")
	}
}

// End to end through the console's loop, as the human types in lox run:
// a loosening refused at :review, re-opened and approved later; the
// policy in force is loosened, and the client sees no pending change.
func TestReopenServeEndToEnd(t *testing.T) {
	h := newHarness(t, uat(), nil)
	d, err := os.MkdirTemp("/tmp", "lkreopen")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	socket := filepath.Join(d, "s")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	looser := uat()
	looser.Tier = "peek"
	h.b.policy = looser
	h.s.CheckPolicy()
	lines := make(chan string)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- h.s.Loop().Serve(ctx, ln, lines) }()
	// type sends a console line; the status call that follows is served
	// after it, on the same goroutine.
	typeLine := func(line string, answers ...string) {
		t.Helper()
		h.io.mu.Lock()
		h.io.answers = append(h.io.answers, answers...)
		h.io.mu.Unlock()
		select {
		case lines <- line:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s not read", line)
		}
		if r := dialAndCall(t, socket, ipc.MethodStatus, map[string]any{}); r.Error != nil {
			t.Fatalf("status %+v", r.Error)
		}
	}
	typeLine(":review", "n")
	if !strings.Contains(h.io.plain(), "policy change refused") {
		t.Fatalf("refusal:\n%s", h.io.plain())
	}
	typeLine(":reopen")
	typeLine(":review", "y")
	cancel()
	<-served
	if !strings.Contains(h.io.plain(), "policy change applied") || h.s.Policy().(fakePolicy).Tier != "peek" || h.s.PolicyPending() {
		t.Fatalf("not loosened (tier %s):\n%s", h.s.Policy().(fakePolicy).Tier, h.io.plain())
	}
	var saved fakePolicy
	if ok, _ := config.LoadApproved(testProduct, h.state, "user-uat", &saved); !ok || saved.Tier != "peek" {
		t.Fatalf("saved %v %+v", ok, saved)
	}
}
