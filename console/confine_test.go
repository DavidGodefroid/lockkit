//go:build unix

package console

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/confine"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/managed"
)

var (
	confined   = &ipc.Confinement{Confined: true}
	hostClient = &ipc.Confinement{Reasons: []string{confine.InContainer, confine.NoHostRuntime}}
)

// conn is a socket connection's context from a peer of the test's uid
// holding groups.
func conn(groups ...int) context.Context {
	return withConn(WithPeer(context.Background(), ipc.Cred{UID: os.Getuid(), GID: os.Getgid(), PID: 1, Groups: groups}))
}

func hello(t *testing.T, h *harness, ctx context.Context, c *ipc.Confinement) ipc.Response {
	t.Helper()
	return h.call(t, ctx, ipc.MethodHello, ipc.HelloParams{ProtocolMajor: ipc.ProtocolMajor, Client: "lockmq", Confinement: c})
}

func unconfinedUAT() fakePolicy {
	p := uat()
	p.Base.Unconfined = true
	return p
}

func TestConfinedServed(t *testing.T) {
	h := newHarness(t, uat(), nil)
	ctx := conn()
	if r := hello(t, h, ctx, confined); r.Error != nil {
		t.Fatalf("hello: %+v", r.Error)
	}
	if r := h.call(t, ctx, ipc.MethodStatus, nil); r.Error != nil {
		t.Fatalf("status: %+v", r.Error)
	}
}

// Unconfined with the default profile: CodeUnconfined naming the reasons,
// audited refused-unconfined, and the connection stays refused.
func TestUnconfinedRefusedByDefault(t *testing.T) {
	h := newHarness(t, uat(), nil)
	ctx := conn()
	r := hello(t, h, ctx, hostClient)
	if r.Error == nil || r.Error.Code != ipc.CodeUnconfined {
		t.Fatalf("hello: %+v", r)
	}
	for _, want := range []string{"refused: this agent does not run confined (in_container: ", "no_host_runtime: ",
		"run it inside lea, or ask the human to set unconfined = true on this non-production profile"} {
		if !strings.Contains(r.Error.Message, want) {
			t.Errorf("message %q lacks %q", r.Error.Message, want)
		}
	}
	rec := h.lastRecord(t)
	if rec["decision"] != DecisionRefusedUnconfined || rec["unconfined"] != true || rec["event"] != "refused" {
		t.Fatalf("audit %v", rec)
	}
	if rs := rec["unconfined_reasons"].([]any); len(rs) != 2 || rs[0] != confine.InContainer {
		t.Fatalf("reasons %v", rs)
	}
	if r := h.call(t, ctx, ipc.MethodStatus, nil); r.Error == nil {
		t.Fatal("a refused connection was served")
	}
}

// unconfined = true on a non-production profile: served, the banner
// printed, every record of the connection marked unconfined.
func TestUnconfinedServedWhenProfileAllows(t *testing.T) {
	h := newHarness(t, unconfinedUAT(), nil)
	ctx := conn()
	if r := hello(t, h, ctx, hostClient); r.Error != nil {
		t.Fatalf("hello: %+v", r.Error)
	}
	if !strings.Contains(h.io.plain(), UnconfinedBanner) {
		t.Fatalf("no banner:\n%s", h.io.plain())
	}
	h.io.answers = []string{"y"}
	before := len(h.records(t))
	h.call(t, ctx, "op.read", map[string]string{"queue": "orders"})
	h.call(t, ctx, ipc.MethodPIIAdd, map[string]string{"pattern": "orders.email"})
	recs := h.records(t)[before:]
	if len(recs) == 0 {
		t.Fatal("no records")
	}
	for _, rec := range recs {
		if rec["unconfined"] != true || rec["unconfined_reasons"] == nil {
			t.Errorf("record of an unconfined connection not marked: %v", rec)
		}
	}
	// A confined connection's records are not marked.
	c2 := conn()
	hello(t, h, c2, confined)
	before = len(h.records(t))
	h.call(t, c2, ipc.MethodPIIAdd, map[string]string{"pattern": "orders.phone"})
	for _, rec := range h.records(t)[before:] {
		if _, ok := rec["unconfined"]; ok {
			t.Errorf("confined record marked: %v", rec)
		}
	}
}

func TestUnconfinedProductionRefusedAtStart(t *testing.T) {
	b := &fakeBackend{policy: prod()}
	b.policy.Base.Unconfined = true
	io := &fakeIO{answers: []string{"y"}, secrets: []string{"pw"}}
	err := Run(context.Background(), testProduct, b, Options{Profile: b.policy.Name, Hub: testHub(t), IO: io, StateDir: t.TempDir(),
		Isolation: runEnv(t), Harden: func() error { return nil }})
	if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "unconfined is never allowed on a production profile") {
		t.Fatalf("Run: %v", err)
	}
	if io.promptCount() != 0 {
		t.Fatalf("prompts %v", io.promptList())
	}
}

func TestRequireConfinedAgentWins(t *testing.T) {
	f, err := managed.Parse([]byte("version = 1\norganisation = \"Example Corp\"\n[family]\nrequire_confined_agent = true\n"))
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, unconfinedUAT(), func(c *ServerConfig) { c.Managed = f })
	r := hello(t, h, conn(), hostClient)
	if r.Error == nil || r.Error.Code != ipc.CodeUnconfined || !strings.Contains(r.Error.Message, "managed configuration requires a confined agent") {
		t.Fatalf("hello: %+v", r)
	}
	if r := hello(t, h, conn(), confined); r.Error != nil {
		t.Fatalf("confined: %+v", r.Error)
	}
}

// A peer holding a runtime gid is unconfined, whatever it reports; its
// primary group counts too.
func TestRuntimeGroupUnconfined(t *testing.T) {
	h := newHarness(t, uat(), func(c *ServerConfig) { c.RuntimeGIDs = []int{999} })
	r := hello(t, h, conn(4, 999), confined)
	if r.Error == nil || r.Error.Code != ipc.CodeUnconfined || !strings.Contains(r.Error.Message, "runtime_group: ") {
		t.Fatalf("hello: %+v", r)
	}
	h2 := newHarness(t, uat(), func(c *ServerConfig) { c.RuntimeGIDs = []int{os.Getgid()} })
	if r := hello(t, h2, conn(), confined); r.Error == nil {
		t.Fatal("primary group in RuntimeGIDs served")
	}
	if r := hello(t, h, conn(4), confined); r.Error != nil {
		t.Fatalf("other groups: %+v", r.Error)
	}
}

func TestOldClientUnconfined(t *testing.T) {
	h := newHarness(t, uat(), nil)
	r := hello(t, h, conn(), nil)
	if r.Error == nil || r.Error.Code != ipc.CodeUnconfined || !strings.Contains(r.Error.Message, "old_client: ") {
		t.Fatalf("hello: %+v", r)
	}
}

// Reason codes are the client's word: unknown ones are dropped, and a
// client may not claim the console's own codes.
func TestUnknownReasonsDropped(t *testing.T) {
	h := newHarness(t, uat(), nil)
	r := hello(t, h, conn(), &ipc.Confinement{Reasons: []string{"\x1b[2Jevil", confine.OldClient}})
	if r.Error == nil || strings.Contains(r.Error.Message, "evil") || strings.Contains(r.Error.Message, "old_client") ||
		!strings.Contains(r.Error.Message, "in_container") {
		t.Fatalf("hello: %+v", r)
	}
}

// (1) On a socket connection no method is served before an accepted hello.
func TestMethodBeforeHelloRefused(t *testing.T) {
	h := newHarness(t, unconfinedUAT(), nil)
	for _, m := range []string{ipc.MethodStatus, ipc.MethodPIIList, "op.read", ipc.MethodLogout} {
		if r := h.call(t, conn(), m, nil); r.Error == nil || r.Error.Code != ipc.CodeInvalidRequest || !strings.Contains(r.Error.Message, "hello first") {
			t.Errorf("%s before hello: %+v", m, r)
		}
	}
	if _, ended := h.s.Ended(); ended {
		t.Fatal("logout before hello ended the session")
	}
}

// (2) The decision is taken again at every request: a policy that becomes
// production cuts an open unconfined connection.
func TestPolicyFlipCutsUnconfined(t *testing.T) {
	h := newHarness(t, unconfinedUAT(), nil)
	ctx := conn()
	if r := hello(t, h, ctx, hostClient); r.Error != nil {
		t.Fatal(r.Error)
	}
	if r := h.call(t, ctx, ipc.MethodStatus, nil); r.Error != nil {
		t.Fatal(r.Error)
	}
	p := unconfinedUAT()
	p.Production = true
	h.s.apply(p)
	r := h.call(t, ctx, ipc.MethodStatus, nil)
	if r.Error == nil || r.Error.Code != ipc.CodeUnconfined || !strings.Contains(r.Error.Message, "never allowed on a production profile") {
		t.Fatalf("after the flip: %+v", r)
	}
	if rec := h.lastRecord(t); rec["decision"] != DecisionRefusedUnconfined {
		t.Fatalf("audit %v", rec)
	}
	// unconfined switched off cuts it too.
	h2 := newHarness(t, unconfinedUAT(), nil)
	ctx2 := conn()
	hello(t, h2, ctx2, hostClient)
	h2.s.apply(uat())
	if r := h2.call(t, ctx2, ipc.MethodStatus, nil); r.Error == nil || r.Error.Code != ipc.CodeUnconfined {
		t.Fatalf("after unconfined off: %+v", r)
	}
}

func TestParseGIDs(t *testing.T) {
	if g, err := ParseGIDs(""); err != nil || g != nil {
		t.Fatalf("empty: %v %v", g, err)
	}
	if g, err := ParseGIDs("999,0"); err != nil || len(g) != 2 || g[0] != 999 || g[1] != 0 {
		t.Fatalf("list: %v %v", g, err)
	}
	for _, bad := range []string{"x", "1,,2", "-1", "1,"} {
		if _, err := ParseGIDs(bad); !errors.Is(err, ErrConfig) {
			t.Errorf("%q accepted", bad)
		}
	}
	in := HubOptions{RuntimeGIDs: "999,998"}
	if a := in.Args(); len(a) != 2 || a[0] != "--runtime-gids" || a[1] != "999,998" || in.Enabled() {
		t.Fatalf("args %v enabled %v", a, in.Enabled())
	}
}
