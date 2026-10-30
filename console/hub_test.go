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

func TestRunRefusesAutoOrPartialHub(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	keyFile := writeHubKey(t, pub)
	for name, o := range map[string]Options{
		"auto":    {Auto: true, Hub: HubOptions{URL: "http://lockhub:8443", KeyFile: keyFile, Instance: "mq-uat", Home: t.TempDir()}},
		"partial": {Hub: HubOptions{URL: "http://lockhub:8443", KeyFile: keyFile, Home: t.TempDir()}},
	} {
		b := &fakeBackend{policy: uat()}
		io := &fakeIO{answers: []string{"y"}}
		o.Profile, o.IO, o.StateDir, o.Isolation, o.Harden = "uat", io, t.TempDir(), runEnv(t), func() error { return nil }
		err := Run(context.Background(), testProduct, b, o)
		if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "--") {
			t.Fatalf("%s: %v, want a flag ErrConfig", name, err)
		}
		if io.promptCount() != 0 || len(b.sessions) != 0 {
			t.Fatalf("%s: prompts %d sessions %d", name, io.promptCount(), len(b.sessions))
		}
	}
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
				Hub bool `json:"hub"`
			}
			if r := Decode(req, &p); r != nil {
				return *r
			}
			sc := Screen{Header: "broker / orders", Body: []string{"WRITE jane.doe@example.com"}}
			if p.Hub {
				h := HubOf(env)
				plan, err := h.Store.Create(plans.Binding{UID: hubCaller.UID, Agent: "dev-1", TokenHash: plans.HashToken(hubCaller.Token),
					PolicyFP: hubPolicyFP, PlanHash: hubPlanHash}, json.RawMessage(`{}`), 0)
				if err != nil {
					return ErrResp(req.ID, ipc.CodeInternal, err.Error())
				}
				sc.Hub = &HubTicket{PlanID: plan.ID, Caller: hubCaller, Risk: ticket.RiskWrite,
					Requester: ticket.Requester{Agent: "dev-1", Session: "s"}, Workspace: "~/w",
					Masked: render.MaskScreen(render.ScreenSource{Header: sc.Header,
						Body: []render.Line{{{Text: "WRITE "}, {Text: "jane.doe@example.com", Value: true, Column: "email"}}}}, render.Masking{})}
			}
			a := env.Approve(ctx, req.ID, sc)
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
			h := HubOf(env)
			plan, _, err := h.Client.Begin(h.Store, p.Ticket, hubCaller, func(*plans.Plan) (string, string, error) {
				return hubPolicyFP, hubPlanHash, nil
			})
			if err != nil {
				return ErrResp(req.ID, ipc.CodeDenied, err.Error())
			}
			b.ran++
			if err := h.Client.Finish(ctx, h.Store, plan.ID, hubCaller, true, ""); err != nil {
				return ErrResp(req.ID, ipc.CodeInternal, err.Error())
			}
			return OKResp(req.ID, "ran")
		},
	}
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
