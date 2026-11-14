//go:build unix

package console

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"
)

const hubInstance = "mq-uat"

var (
	hubPlanHash = "sha256:" + strings.Repeat("1", 64)
	hubPolicyFP = "sha256:" + strings.Repeat("2", 64)
	hubCaller   = plans.Caller{UID: 1000, Token: "tok"}
)

func TestHubOptionsFlags(t *testing.T) {
	var o HubOptions
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	o.Register(fs)
	if err := fs.Parse([]string{"--hub", "http://lockhub:8443", "--hub-key-file", "/run/lockfamily/hub.pub", "--instance", "mq-uat"}); err != nil {
		t.Fatal(err)
	}
	if o != (HubOptions{URL: "http://lockhub:8443", KeyFile: "/run/lockfamily/hub.pub", Instance: "mq-uat"}) || !o.Enabled() {
		t.Fatalf("parsed %+v", o)
	}
	if err := o.check(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []HubOptions{
		{URL: "http://lockhub:8443"},
		{URL: "http://lockhub:8443", KeyFile: "/k"},
		{KeyFile: "/k", Instance: "mq-uat"},
		{URL: "http://lockhub:8443", Instance: "mq-uat"},
		{URL: "http://lockhub:8443", KeyFile: "/k", Instance: "../x"},
	} {
		if err := bad.check(); !errors.Is(err, ErrConfig) {
			t.Errorf("%+v: %v, want ErrConfig", bad, err)
		}
	}
	if (HubOptions{}).Enabled() {
		t.Error("no flag is hub mode")
	}
}

// A console is hub-attached only: without its hub flags, with only some
// of them, Run refuses before any prompt, session or file.
func TestRunRefusesNoHubOrPartialHub(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	keyFile := writeHubKey(t, pub)
	for name, tc := range map[string]struct {
		o    Options
		want string
	}{
		"none":    {Options{}, "configuration error: the console is launched by `lox run` only: --hub, --hub-key-file and --instance are required"},
		"partial": {Options{Hub: HubOptions{URL: "http://lockhub:8443", KeyFile: keyFile, Home: t.TempDir()}}, "launched by `lox run` only"},
	} {
		b := &fakeBackend{policy: uat()}
		io := &fakeIO{answers: []string{"y"}}
		o := tc.o
		state := t.TempDir()
		o.Profile, o.IO, o.StateDir, o.Isolation, o.Harden = "uat", io, state, runEnv(t), func() error { return nil }
		err := Run(context.Background(), testProduct, b, o)
		if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v, want %q", name, err, tc.want)
		}
		if name != "auto" && !errors.Is(err, ErrNoHub) {
			t.Fatalf("%s: %v, want ErrNoHub", name, err)
		}
		if io.promptCount() != 0 || len(b.sessions) != 0 || io.plain() != "" {
			t.Fatalf("%s: prompts %d sessions %d output %q", name, io.promptCount(), len(b.sessions), io.plain())
		}
		if entries, _ := os.ReadDir(state); len(entries) != 0 {
			t.Fatalf("%s: state written: %v", name, entries)
		}
	}
}

// testHub is a hub for a console under Run (hubtest), and the options
// that attach the console to it.
func testHub(t *testing.T) HubOptions {
	t.Helper()
	home := t.TempDir()
	key, err := hubclient.InstanceKey(home, hubInstance)
	if err != nil {
		t.Fatal(err)
	}
	hub := hubtest.New(t, hubInstance, key.Public().(ed25519.PublicKey))
	return HubOptions{URL: hub.URL(), KeyFile: writeHubKey(t, hub.Pub), Instance: hubInstance, Home: home}
}

// hubBackend is a product in hub mode: op.write plans and asks the hub,
// op.run runs the decided ticket.
type hubBackend struct {
	fakeBackend
	ran int
}

func (b *hubBackend) Methods() map[string]Handler {
	return map[string]Handler{
		"op.write": func(ctx context.Context, req ipc.Request, env Env) ipc.Response {
			var p struct {
				Hub  bool        `json:"hub"`
				Risk ticket.Risk `json:"risk"`
				Kind ticket.Kind `json:"kind"`
			}
			if r := Decode(req, &p); r != nil {
				return *r
			}
			sc := Screen{Header: "broker / orders", Body: []string{"WRITE jane.doe@example.com"}}
			planHash := hubPlanHash
			switch {
			case p.Kind != "":
				planHash = "sha256:" + strings.Repeat("4", 64) // another plan: an action
			case p.Risk == "":
			default:
				planHash = "sha256:" + strings.Repeat("3", 64) // another plan: a scope
			}
			if p.Risk == "" {
				p.Risk = ticket.RiskWrite
			}
			if p.Hub {
				h := HubOf(env)
				plan, err := h.Store.Create(plans.Binding{UID: hubCaller.UID, Agent: "dev-1", TokenHash: plans.HashToken(hubCaller.Token),
					PolicyFP: hubPolicyFP, PlanHash: planHash}, json.RawMessage(`{}`), 0)
				if err != nil {
					return ErrResp(req.ID, ipc.CodeInternal, err.Error())
				}
				sc.Hub = &HubTicket{PlanID: plan.ID, Caller: hubCaller, Risk: p.Risk,
					Requester: ticket.Requester{Agent: "dev-1", Session: "s"}, Workspace: "~/w",
					Masked: render.MaskScreen(render.ScreenSource{Header: sc.Header,
						Body: []render.Line{{{Text: "WRITE "}, {Text: "jane.doe@example.com", Value: true, Column: "email"}}}}, render.Masking{})}
				if p.Kind != "" {
					sc.Hub.Kind = p.Kind
					if p.Kind == ticket.KindAction {
						sc.Hub.Subject = &ticket.Subject{Profile: "uat", Verb: "publish", Target: "orders"}
					}
				}
			}
			a := env.Approve(ctx, req.ID, sc)
			if a.Pending != nil && a.Decided {
				// Decided within the hub's short wait: run it now.
				return b.run(ctx, req.ID, a.Pending.Ticket, env)
			}
			if !a.Approved {
				return a.Refusal
			}
			return OKResp(req.ID, "done")
		},
		"op.run": func(ctx context.Context, req ipc.Request, env Env) ipc.Response {
			var p struct {
				Ticket string `json:"ticket"`
			}
			if r := Decode(req, &p); r != nil {
				return *r
			}
			return b.run(ctx, req.ID, p.Ticket, env)
		},
	}
}

// run runs the plan of decided ticket tk.
func (b *hubBackend) run(ctx context.Context, id int64, tk string, env Env) ipc.Response {
	h := HubOf(env)
	plan, _, err := h.Client.Begin(h.Store, tk, hubCaller, func(*plans.Plan) (string, string, error) {
		return hubPolicyFP, hubPlanHash, nil
	})
	if err != nil {
		return ErrResp(id, ipc.CodeDenied, err.Error())
	}
	b.ran++
	if err := h.Client.Finish(ctx, h.Store, plan.ID, hubCaller, true, ""); err != nil {
		return ErrResp(id, ipc.CodeInternal, err.Error())
	}
	return OKResp(id, "ran")
}

func writeHubKey(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hub.pub")
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// Run in hub mode end to end: the request is pushed to the hub masked and
// answered pending with no prompt; once the hub approves, op.run runs it
// once and the hub hears it was consumed.
func TestRunHubModeEndToEnd(t *testing.T) {
	env := runEnv(t)
	home, state := t.TempDir(), t.TempDir()
	key, err := hubclient.InstanceKey(home, hubInstance)
	if err != nil {
		t.Fatal(err)
	}
	hub := hubtest.New(t, hubInstance, key.Public().(ed25519.PublicKey))
	b := &hubBackend{fakeBackend: fakeBackend{policy: uat()}}
	io := &fakeIO{answers: []string{"y"}, secrets: []string{"s3cret"}}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		done <- Run(ctx, testProduct, b, Options{Profile: "uat", IO: io, StateDir: state, Isolation: env,
			Harden: func() error { return nil }, Quantum: -1, Ready: func(s string) { ready <- s },
			Hub: HubOptions{URL: hub.URL(), KeyFile: writeHubKey(t, hub.Pub), Instance: hubInstance, Home: home}})
	}()
	var socket string
	select {
	case socket = <-ready:
	case err := <-done:
		t.Fatalf("Run: %v\n%s", err, io.plain())
	case <-time.After(10 * time.Second):
		t.Fatal("no socket")
	}
	prompts := io.promptCount()

	// A product that did not prepare a hub ticket is refused, never asked.
	if r := dialAndCall(t, socket, "op.write", map[string]bool{"hub": false}); r.Error == nil || r.Error.Code != ipc.CodeInternal {
		t.Fatalf("no hub ticket: %+v %s", r.Error, r.Result)
	}
	r := dialAndCall(t, socket, "op.write", map[string]bool{"hub": true})
	if r.Error != nil {
		t.Fatalf("op.write: %+v\n%s", r.Error, io.plain())
	}
	m := pendingOf(t, r.Result)
	if m["status"] != "pending" || m["ticket"] == "" || m["instance"] != hubInstance || io.promptCount() != prompts {
		t.Fatalf("result %v prompts %d→%d", m, prompts, io.promptCount())
	}
	raw := hub.Ticket(m["ticket"])
	if raw == nil || strings.Contains(string(raw), "jane.doe") {
		t.Fatalf("hub ticket: %s", raw)
	}
	tk, err := ticket.VerifyTicket(key.Public().(ed25519.PublicKey), raw)
	if err != nil || tk.Source.Lock != testProduct.Name || tk.Source.Instance != hubInstance || tk.Risk != ticket.RiskWrite {
		t.Fatalf("ticket %+v %v", tk, err)
	}
	// A grant ticket keeps NeverAuto, though the screen does not ask it.
	g := pendingOf(t, dialAndCall(t, socket, "op.write", map[string]any{"hub": true, "risk": ticket.RiskGrant}).Result)
	if gt, err := ticket.VerifyTicket(key.Public().(ed25519.PublicKey), hub.Ticket(g["ticket"])); err != nil || gt.Risk != ticket.RiskGrant || !gt.Flags.NeverAuto {
		t.Fatalf("grant ticket %+v %v", gt, err)
	}
	// A kind makes a version-2 ticket with its subject; a connect ticket
	// is the lock's own, never a plan's.
	ka := pendingOf(t, dialAndCall(t, socket, "op.write", map[string]any{"hub": true, "kind": ticket.KindAction}).Result)
	if at, err := ticket.VerifyTicket(key.Public().(ed25519.PublicKey), hub.Ticket(ka["ticket"])); err != nil ||
		at.V != ticket.VersionKinds || at.Kind != ticket.KindAction || at.Subject == nil || at.Subject.Verb != "publish" {
		t.Fatalf("action ticket %+v %v", at, err)
	}
	if r := dialAndCall(t, socket, "op.write", map[string]any{"hub": true, "kind": ticket.KindConnect}); r.Error == nil {
		t.Fatalf("a plan's connect ticket: %s", r.Result)
	}

	if r := dialAndCall(t, socket, "op.run", map[string]string{"ticket": m["ticket"]}); r.Error == nil {
		t.Fatal("ran before a decision")
	}
	hub.Decide(m["ticket"], ticket.Approved, "")
	deadline := time.Now().Add(10 * time.Second)
	for {
		r := dialAndCall(t, socket, "op.run", map[string]string{"ticket": m["ticket"]})
		if r.Error == nil {
			break
		}
		if !strings.Contains(r.Error.Message, "no decision yet") || time.Now().After(deadline) {
			t.Fatalf("op.run: %+v", r.Error)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if b.ran != 1 || !hub.Consumed(m["ticket"]) {
		t.Fatalf("ran %d consumed %v", b.ran, hub.Consumed(m["ticket"]))
	}
	if r := dialAndCall(t, socket, "op.run", map[string]string{"ticket": m["ticket"]}); r.Error == nil {
		t.Fatal("ran twice")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// A ticket an auto rule decides as the hub accepts it is decided within
// the console's short wait (Approval.Decided): the product runs it in the
// same call, and the agent never hears pending (#162).
func TestRunHubAutoDecidedRunsInOneCall(t *testing.T) {
	env := runEnv(t)
	home := t.TempDir()
	key, err := hubclient.InstanceKey(home, hubInstance)
	if err != nil {
		t.Fatal(err)
	}
	hub := hubtest.New(t, hubInstance, key.Public().(ed25519.PublicKey))
	hub.AutoDecide("default:write")
	b := &hubBackend{fakeBackend: fakeBackend{policy: uat()}}
	io := &fakeIO{answers: []string{"y"}, secrets: []string{"s3cret"}}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		done <- Run(ctx, testProduct, b, Options{Profile: "uat", IO: io, StateDir: t.TempDir(), Isolation: env,
			Harden: func() error { return nil }, Quantum: -1, Ready: func(s string) { ready <- s },
			Hub: HubOptions{URL: hub.URL(), KeyFile: writeHubKey(t, hub.Pub), Instance: hubInstance, Home: home}})
	}()
	var socket string
	select {
	case socket = <-ready:
	case err := <-done:
		t.Fatalf("Run: %v\n%s", err, io.plain())
	case <-time.After(10 * time.Second):
		t.Fatal("no socket")
	}
	prompts := io.promptCount()
	r := dialAndCall(t, socket, "op.write", map[string]bool{"hub": true})
	if r.Error != nil {
		t.Fatalf("op.write: %+v\n%s", r.Error, io.plain())
	}
	var got string
	if err := json.Unmarshal(r.Result, &got); err != nil || got != "ran" {
		t.Fatalf("op.write answered %s, want the run's result", r.Result)
	}
	tickets := hub.Tickets()
	if b.ran != 1 || len(tickets) != 1 || !hub.Consumed(tickets[0]) || io.promptCount() != prompts {
		t.Fatalf("ran %d tickets %v prompts %d→%d", b.ran, tickets, prompts, io.promptCount())
	}
	cancel()
	<-done
}

// With the hub down the request is pending all the same, never asked here.
func TestRunHubDownStaysPending(t *testing.T) {
	env := runEnv(t)
	home := t.TempDir()
	key, _ := hubclient.InstanceKey(home, hubInstance)
	hub := hubtest.New(t, hubInstance, key.Public().(ed25519.PublicKey))
	url := hub.URL()
	hub.Close()
	b := &hubBackend{fakeBackend: fakeBackend{policy: uat()}}
	io := &fakeIO{answers: []string{"y", "y", "y"}, secrets: []string{"s3cret"}}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		done <- Run(ctx, testProduct, b, Options{Profile: "uat", IO: io, StateDir: t.TempDir(), Isolation: env,
			Harden: func() error { return nil }, Quantum: -1, Ready: func(s string) { ready <- s },
			Hub: HubOptions{URL: url, KeyFile: writeHubKey(t, hub.Pub), Instance: hubInstance, Home: home}})
	}()
	var socket string
	select {
	case socket = <-ready:
	case err := <-done:
		t.Fatalf("Run: %v\n%s", err, io.plain())
	case <-time.After(10 * time.Second):
		t.Fatal("no socket")
	}
	prompts := io.promptCount()
	r := dialAndCall(t, socket, "op.write", map[string]bool{"hub": true})
	if r.Error != nil || pendingOf(t, r.Result)["status"] != "pending" || io.promptCount() != prompts {
		t.Fatalf("hub down: %+v %s prompts %d→%d", r.Error, r.Result, prompts, io.promptCount())
	}
	cancel()
	<-done
}

// Run releases its hub when it returns: a console started again on the
// same state opens the plans store (one store per directory, #60).
func TestRunReleasesHub(t *testing.T) {
	home, state := t.TempDir(), t.TempDir()
	key, _ := hubclient.InstanceKey(home, hubInstance)
	hub := hubtest.New(t, hubInstance, key.Public().(ed25519.PublicKey))
	o := HubOptions{URL: hub.URL(), KeyFile: writeHubKey(t, hub.Pub), Instance: hubInstance, Home: home}
	for i := 0; i < 2; i++ {
		env := runEnv(t)
		b := &hubBackend{fakeBackend: fakeBackend{policy: uat()}}
		io := &fakeIO{answers: []string{"y"}, secrets: []string{"s3cret"}}
		ready := make(chan string, 1)
		done := make(chan error, 1)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			done <- Run(ctx, testProduct, b, Options{Profile: "uat", IO: io, StateDir: state, Isolation: env,
				Harden: func() error { return nil }, Quantum: -1, Ready: func(s string) { ready <- s }, Hub: o})
		}()
		select {
		case <-ready:
		case err := <-done:
			cancel()
			t.Fatalf("start %d: %v\n%s", i+1, err, io.plain())
		case <-time.After(10 * time.Second):
			t.Fatal("no socket")
		}
		cancel()
		<-done
	}
}

// Reveal (Ctrl-O) end to end through Run: a facade the lock pins gets the
// clear screen sealed to its ephemeral key, the hub only relays
// ciphertext, and the reveal is audited. The agent's socket has no decide
// and no reveal method (I5).
func TestRunHubReveal(t *testing.T) {
	env := runEnv(t)
	home, state := t.TempDir(), t.TempDir()
	key, _ := hubclient.InstanceKey(home, hubInstance)
	hub := hubtest.New(t, hubInstance, key.Public().(ed25519.PublicKey))
	fpub, fkey, _ := ed25519.GenerateKey(rand.Reader)
	ff := filepath.Join(t.TempDir(), "facades.json")
	fb, _ := json.Marshal(ticket.FacadeSet{V: 1, Facades: []ticket.FacadeKey{{Facade: "tty", Key: base64.StdEncoding.EncodeToString(fpub)}}})
	if err := os.WriteFile(ff, fb, 0o644); err != nil {
		t.Fatal(err)
	}
	b := &hubBackend{fakeBackend: fakeBackend{policy: uat()}}
	io := &fakeIO{answers: []string{"y"}, secrets: []string{"s3cret"}}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		done <- Run(ctx, testProduct, b, Options{Profile: "uat", IO: io, StateDir: state, Isolation: env,
			Harden: func() error { return nil }, Quantum: -1, Ready: func(s string) { ready <- s },
			Hub: HubOptions{URL: hub.URL(), KeyFile: writeHubKey(t, hub.Pub), Instance: hubInstance, Home: home, FacadeKeysFile: ff}})
	}()
	var socket string
	select {
	case socket = <-ready:
	case err := <-done:
		t.Fatalf("Run: %v\n%s", err, io.plain())
	case <-time.After(10 * time.Second):
		t.Fatal("no socket")
	}
	m := pendingOf(t, dialAndCall(t, socket, "op.write", map[string]bool{"hub": true}).Result)
	id := m["ticket"]
	for _, method := range []string{"ticket.decide", "decide", "reveal", "ticket.reveal", "hub.reveal", "renew", "ticket.renew"} {
		r := dialAndCall(t, socket, method, map[string]string{"ticket": id, "decision": "approved"})
		if r.Error == nil || r.Error.Code != ipc.CodeMethodNotFound {
			t.Fatalf("%s on the agent socket: %+v %s", method, r.Error, r.Result)
		}
	}
	tk, err := ticket.VerifyTicket(key.Public().(ed25519.PublicKey), hub.Ticket(id))
	if err != nil {
		t.Fatal(err)
	}
	rk, priv, _ := ticket.NewRevealKey(fkey, ticket.FacadeTTY, tk, time.Now())
	rid := hub.Request(id, ticket.RequestReveal, rk, nil)
	deadline := time.Now().Add(15 * time.Second)
	for hub.Answer(rid) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("no answer\n%s", io.plain())
		}
		time.Sleep(50 * time.Millisecond)
	}
	ans := hub.Answer(rid)
	if strings.Contains(string(ans), "jane.doe") || strings.Contains(string(hub.Ticket(id)), "jane.doe") {
		t.Fatal("clear value at the hub")
	}
	var a struct {
		Reveal json.RawMessage `json:"reveal"`
	}
	_ = json.Unmarshal(ans, &a)
	s, err := ticket.OpenReveal(key.Public().(ed25519.PublicKey), priv, rk, a.Reveal)
	if err != nil || len(s.Body) != 1 || s.Body[0] != "WRITE jane.doe@example.com" {
		t.Fatalf("%+v %v (%s)", s, err, ans)
	}
	cancel()
	<-done
	raw, _ := os.ReadFile(filepath.Join(state, testProduct.Name, "audit.log"))
	if !strings.Contains(string(raw), `"event":"reveal"`) || !strings.Contains(string(raw), `"decision":"sealed"`) || strings.Contains(string(raw), "jane.doe") {
		t.Fatalf("audit:\n%s", raw)
	}
}

// OnHub is told the hub before any request is served.
func TestRunOnHub(t *testing.T) {
	env := runEnv(t)
	home := t.TempDir()
	key, _ := hubclient.InstanceKey(home, hubInstance)
	hub := hubtest.New(t, hubInstance, key.Public().(ed25519.PublicKey))
	b := &hubBackend{fakeBackend: fakeBackend{policy: uat()}}
	io := &fakeIO{answers: []string{"y"}, secrets: []string{"s3cret"}}
	got := make(chan *Hub, 1)
	ready := make(chan string, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		done <- Run(ctx, testProduct, b, Options{Profile: "uat", IO: io, StateDir: t.TempDir(), Isolation: env,
			Harden: func() error { return nil }, Quantum: -1, Ready: func(s string) { ready <- s },
			OnHub: func(h *Hub) {
				if len(ready) != 0 {
					t.Error("OnHub after the socket listened")
				}
				got <- h
			},
			Hub: HubOptions{URL: hub.URL(), KeyFile: writeHubKey(t, hub.Pub), Instance: hubInstance, Home: home}})
	}()
	select {
	case h := <-got:
		if h == nil || h.Client == nil || h.Instance != hubInstance {
			t.Fatalf("hub %+v", h)
		}
	case err := <-done:
		t.Fatalf("Run: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("OnHub not called")
	}
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("no socket")
	}
	cancel()
	<-done
}

// Canaries: a token pasted in a hub flag never reaches an error, the
// console's lines or the command line Args builds.
const (
	echoCanary    = "glsa_CanarySecretToken123"
	echoCanaryURL = "https://user:glsa_Canary@h/path?token=glsa_Canary"
)

func TestHubOptionsNeverEchoValues(t *testing.T) {
	for _, o := range []HubOptions{
		{URL: echoCanaryURL, KeyFile: "/k", Instance: "mq-uat"},
		{URL: "https://h/path?token=" + echoCanary, KeyFile: "/k", Instance: "mq-uat"},
		{URL: "https://h/" + echoCanary, KeyFile: "/k", Instance: "mq-uat"},
		{URL: "https://h#" + echoCanary, KeyFile: "/k", Instance: "mq-uat"},
		{URL: "https://h;" + echoCanary, KeyFile: "/k", Instance: "mq-uat"},
		{URL: "https://h&token=" + echoCanary, KeyFile: "/k", Instance: "mq-uat"},
		{URL: "https://lockhub:8443", KeyFile: "/k", Instance: echoCanary},
		{URL: "https://lockhub:8443", KeyFile: "/k", Instance: "mq-uat", DevicesFile: "/d", RequireDevice: "write," + echoCanary},
	} {
		err := o.check()
		if !errors.Is(err, ErrConfig) || strings.Contains(err.Error(), "glsa_Canary") || !strings.Contains(err.Error(), "--") {
			t.Errorf("%+v: %v (want an ErrConfig naming the flag, not the value)", o, err)
		}
		if a := o.Args(); strings.Contains(strings.Join(a, " "), "Canary") {
			t.Errorf("Args %q carries the token", a)
		}
	}
	// Args passes the hub as scheme://host[:port] only; a URL OpenHub would
	// refuse goes as one the new console refuses too.
	for in, want := range map[string]string{
		"https://lockhub:8443/": "https://lockhub:8443", "http://lockhub:8443": "http://lockhub:8443",
		echoCanaryURL: refusedHubURL, "https://h/path?token=" + echoCanary: refusedHubURL,
	} {
		o := HubOptions{URL: in, KeyFile: "/k", Instance: "mq-uat"}
		args := o.Args()
		if len(args) < 2 || args[0] != "--hub" || args[1] != want {
			t.Errorf("Args(%s) = %q, want --hub %s", in, args, want)
		}
		if want == refusedHubURL {
			o.URL = args[1]
			if err := o.check(); !errors.Is(err, ErrConfig) {
				t.Errorf("%s passed on is not refused: %v", refusedHubURL, err)
			}
		}
	}
}

// Run with a token in the hub URL is refused before any prompt, and the
// token reaches neither the error nor the terminal.
func TestRunHubURLNeverEchoed(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	keyFile := writeHubKey(t, pub)
	for _, u := range []string{echoCanaryURL, "https://h/?token=" + echoCanary, "https://h/" + echoCanary} {
		b := &fakeBackend{policy: uat()}
		io := &fakeIO{answers: []string{"y"}}
		err := Run(context.Background(), testProduct, b, Options{Profile: "uat", IO: io, StateDir: t.TempDir(), Isolation: runEnv(t),
			Harden: func() error { return nil }, Hub: HubOptions{URL: u, KeyFile: keyFile, Instance: "mq-uat", Home: t.TempDir()}})
		if !errors.Is(err, ErrConfig) || strings.Contains(err.Error(), "Canary") || strings.Contains(io.plain(), "Canary") {
			t.Errorf("%s: %v\n%s", u, err, io.plain())
		}
	}
}

// The start line names the hub as scheme://host[:port], and the errors of
// a hub that cannot be reached do not quote the request URL.
func TestRunHubStartLineAndErrorsShowHostOnly(t *testing.T) {
	env := runEnv(t)
	home := t.TempDir()
	key, _ := hubclient.InstanceKey(home, hubInstance)
	hub := hubtest.New(t, hubInstance, key.Public().(ed25519.PublicKey))
	base := hub.URL()
	hub.Close()
	b := &hubBackend{fakeBackend: fakeBackend{policy: uat()}}
	io := &fakeIO{answers: []string{"y", "y", "y"}, secrets: []string{"s3cret"}}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		done <- Run(ctx, testProduct, b, Options{Profile: "uat", IO: io, StateDir: t.TempDir(), Isolation: env,
			Harden: func() error { return nil }, Quantum: -1, Ready: func(s string) { ready <- s },
			Hub: HubOptions{URL: base + "/", KeyFile: writeHubKey(t, hub.Pub), Instance: hubInstance, Home: home}})
	}()
	var socket string
	select {
	case socket = <-ready:
	case err := <-done:
		t.Fatalf("Run: %v\n%s", err, io.plain())
	case <-time.After(10 * time.Second):
		t.Fatal("no socket")
	}
	if r := dialAndCall(t, socket, "op.write", map[string]bool{"hub": true}); r.Error != nil {
		t.Fatalf("op.write: %+v", r.Error)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(io.plain(), "hub unreachable") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	out := io.plain()
	if !strings.Contains(out, "Requests are decided on lockhub at "+base+" as "+hubInstance) {
		t.Errorf("no start line with %s:\n%s", base, out)
	}
	if !strings.Contains(out, "hub unreachable") || strings.Contains(out, "/v1/") {
		t.Errorf("hub errors (want unreachable, without the request URL):\n%s", out)
	}
}

// Args passes neither an invalid --instance nor an invalid
// --require-device on; the console started with the placeholder refuses it.
func TestHubArgsDropInvalidValues(t *testing.T) {
	o := HubOptions{URL: "https://lockhub:8443", KeyFile: "/k", Instance: echoCanary, DevicesFile: "/d", RequireDevice: "write," + echoCanary}
	a := o.Args()
	if strings.Contains(strings.Join(a, " "), "Canary") {
		t.Fatalf("Args %q", a)
	}
	var back HubOptions
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	back.Register(fs)
	if err := fs.Parse(a); err != nil {
		t.Fatal(err)
	}
	if err := back.check(); !errors.Is(err, ErrConfig) {
		t.Errorf("placeholders accepted: %v", err)
	}
	back.Instance = "mq-uat"
	if err := back.check(); !errors.Is(err, ErrConfig) {
		t.Errorf("--require-device placeholder accepted: %v", err)
	}
	ok := HubOptions{URL: "https://lockhub:8443", KeyFile: "/k", Instance: "mq-uat", DevicesFile: "/d", RequireDevice: "write, prod-write"}
	if a := strings.Join(ok.Args(), " "); !strings.Contains(a, "--instance mq-uat") || !strings.Contains(a, "--require-device write, prod-write") {
		t.Errorf("valid values not passed on: %s", a)
	}
}

// Hub-attached, the console's own decisions are still asked on its
// terminal: a policy change at :review and :unmask go to the approver the
// hub approver wraps, never to the hub.
func TestHubConsoleOwnDecisionsOnTerminal(t *testing.T) {
	hub := &Hub{lock: testProduct.Name, Instance: hubInstance, now: time.Now}
	h := newHarness(t, uat(), func(c *ServerConfig) {
		c.Hub = hub
		c.Approver = hub.Approver(NewTypedApprover(c.IO))
	})
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":unmask")
	if !h.s.UnmaskAllowed() || h.io.promptCount() != 1 {
		t.Fatalf("unmask %v prompts %d\n%s", h.s.UnmaskAllowed(), h.io.promptCount(), h.io.plain())
	}
	if rec := h.lastRecord(t); rec["event"] != "unmask" || rec["decision"] != "allowed" || rec["approval"] != "session" {
		t.Fatalf("unmask audit: %v", rec)
	}
	looser := uat()
	looser.Tier = "peek"
	h.b.policy = looser
	h.s.CheckPolicy()
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	if h.s.approved.(fakePolicy).Tier != "peek" || h.io.promptCount() != 2 {
		t.Fatalf("policy change: tier %q prompts %d\n%s", h.s.approved.(fakePolicy).Tier, h.io.promptCount(), h.io.plain())
	}
	if rec := h.lastRecord(t); rec["event"] != "policy" || rec["decision"] != "applied" || rec["approval"] != "session" {
		t.Fatalf("policy audit: %v", rec)
	}
}

// The profile's ticket limits reach the hub client when the console
// starts and whenever a policy comes in force: a raise only once the
// human approved it, a cut at once.
func TestServerAppliesTicketLimits(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	hub := hubtest.New(t, hubInstance, pub)
	c, err := hubclient.New(hubclient.Config{URL: hub.URL(), Instance: hubInstance, Key: priv, HubKey: hub.Pub,
		StateFile: filepath.Join(t.TempDir(), "state.json")})
	if err != nil {
		t.Fatal(err)
	}
	p := uat()
	p.Base.TicketsPerWindow = 60
	h := newHarness(t, p, func(cfg *ServerConfig) { cfg.Hub = &Hub{Client: c, Instance: hubInstance} })
	if l := c.Limits(); l.RateN != 60 || l.MaxPending != hubclient.MaxPending || l.RateWindow != hubclient.RateWindow {
		t.Fatalf("start: %+v", l)
	}

	raised := p
	raised.Base.TicketsPerWindow = 90
	h.b.policy = raised
	h.s.CheckPolicy()
	if !h.s.PolicyPending() || c.Limits().RateN != 60 {
		t.Fatalf("raise applied without review: %+v", c.Limits())
	}
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	if c.Limits().RateN != 90 {
		t.Fatalf("approved raise: %+v", c.Limits())
	}

	cut := raised
	cut.Base.TicketsPerWindow, cut.Base.MaxPending = 10, 5
	h.b.policy = cut
	h.s.CheckPolicy()
	if l := c.Limits(); h.s.PolicyPending() || l.RateN != 10 || l.MaxPending != 5 {
		t.Fatalf("cut: %+v", l)
	}
}

// On production, a raise of the ticket limits waits for the typed name.
func TestServerTicketLimitsProductionTypedName(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	hub := hubtest.New(t, hubInstance, pub)
	c, err := hubclient.New(hubclient.Config{URL: hub.URL(), Instance: hubInstance, Key: priv, HubKey: hub.Pub,
		StateFile: filepath.Join(t.TempDir(), "state.json")})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, prod(), func(cfg *ServerConfig) { cfg.Hub = &Hub{Client: c, Instance: hubInstance} })
	raised := prod()
	raised.Base.TicketsPerWindow = 60
	h.b.policy = raised
	h.s.CheckPolicy()
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	if c.Limits().RateN != hubclient.RateN {
		t.Fatalf("raise applied on a yes: %+v", c.Limits())
	}
	// A refused loosening waits for the files to change.
	raised.Base.TicketsPerWindow = 61
	h.b.policy = raised
	h.s.CheckPolicy()
	h.io.answers = []string{"prod"}
	h.s.Command(context.Background(), ":review")
	if c.Limits().RateN != 61 {
		t.Fatalf("raise not applied with the typed name: %+v", c.Limits())
	}
}

// A ticket of an unconfined connection carries flags.unconfined; one of a
// confined connection does not.
func TestRunHubTicketUnconfined(t *testing.T) {
	env := runEnv(t)
	home, state := t.TempDir(), t.TempDir()
	key, err := hubclient.InstanceKey(home, hubInstance)
	if err != nil {
		t.Fatal(err)
	}
	hub := hubtest.New(t, hubInstance, key.Public().(ed25519.PublicKey))
	b := &hubBackend{fakeBackend: fakeBackend{policy: unconfinedUAT()}}
	io := &fakeIO{answers: []string{"y"}, secrets: []string{"s3cret"}}
	ready := make(chan string, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		done <- Run(ctx, testProduct, b, Options{Profile: "uat", IO: io, StateDir: state, Isolation: env,
			Harden: func() error { return nil }, Quantum: -1, Ready: func(s string) { ready <- s },
			Hub: HubOptions{URL: hub.URL(), KeyFile: writeHubKey(t, hub.Pub), Instance: hubInstance, Home: home}})
	}()
	var socket string
	select {
	case socket = <-ready:
	case err := <-done:
		t.Fatalf("Run: %v\n%s", err, io.plain())
	case <-time.After(10 * time.Second):
		t.Fatal("no socket")
	}
	if !strings.Contains(io.plain(), UnconfinedBanner) {
		t.Fatalf("no banner at start:\n%s", io.plain())
	}
	for _, tc := range []struct {
		conf *ipc.Confinement
		kind ticket.Kind
		want bool
	}{{&ipc.Confinement{Reasons: []string{"in_container"}}, "", true}, {&ipc.Confinement{Confined: true}, ticket.KindAction, false}} {
		params := map[string]any{"hub": true}
		if tc.kind != "" {
			params["kind"] = tc.kind
		}
		r := dialAndCallAs(t, socket, tc.conf, "op.write", params)
		if r.Error != nil {
			t.Fatalf("op.write: %+v", r.Error)
		}
		raw := hub.Ticket(pendingOf(t, r.Result)["ticket"])
		tk, err := ticket.VerifyTicket(key.Public().(ed25519.PublicKey), raw)
		if err != nil || tk.Flags.Unconfined != tc.want {
			t.Fatalf("ticket %s: %v", raw, err)
		}
		if !tc.want && strings.Contains(string(raw), "unconfined") {
			t.Fatalf("a confined ticket names unconfined: %s", raw)
		}
	}
}
