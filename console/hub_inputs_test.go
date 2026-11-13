//go:build unix

package console

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/hubclient/hubtest"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// inputsHub is a console's hub mode on a hubtest hub, without Run.
func inputsHub(t *testing.T) (*Hub, *hubtest.Hub, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	hub := hubtest.New(t, "mq-uat", pub)
	st, err := plans.Open(filepath.Join(t.TempDir(), "plans"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	c, err := hubclient.New(hubclient.Config{URL: hub.URL(), Instance: "mq-uat", Key: priv, HubKey: hub.Pub,
		StateFile: filepath.Join(t.TempDir(), "state.json")})
	if err != nil {
		t.Fatal(err)
	}
	return &Hub{Client: c, Store: st, Instance: "mq-uat", lock: "lockfile", now: time.Now}, hub, pub
}

// inputsPlans counts the plans of inputsDecisionFor: each has a plan
// hash of its own (a pending plan with the same hash lends its ticket).
var inputsPlans int

func inputsDecisionFor(t *testing.T, h *Hub, kind ticket.Kind, subj *ticket.Subject, inputs ...string) Decision {
	t.Helper()
	inputsPlans++
	hash, _ := ticket.HashOf(map[string]any{"plan": inputsPlans})
	p, err := h.Store.Create(plans.Binding{UID: hubCaller.UID, Agent: "dev-1", TokenHash: plans.HashToken(hubCaller.Token),
		PolicyFP: hubPolicyFP, PlanHash: hash}, json.RawMessage(`{}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	return Decision{Screen: &Screen{Header: "files / move", Body: []string{"MOVE a TO :dest"},
		Hub: &HubTicket{PlanID: p.ID, Caller: hubCaller, Risk: ticket.RiskWrite, Kind: kind, Subject: subj, Inputs: inputs,
			Masked: render.MaskScreen(render.ScreenSource{Header: "files / move", Body: []render.Line{{{Text: "MOVE a TO :dest"}}}}, render.Masking{})}}}
}

func TestHubTicketInputs(t *testing.T) {
	ctx := context.Background()
	h, hub, lockPub := inputsHub(t)
	a := h.Approver(nil)
	subj := &ticket.Subject{Profile: "uat", Verb: "move", Target: "a"}
	d := inputsDecisionFor(t, h, ticket.KindAction, subj, "src", "dest")
	pend, err := a.Submit(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	tk, err := ticket.VerifyTicket(lockPub, hub.Ticket(pend.Ticket))
	if err != nil {
		t.Fatal(err)
	}
	if !tk.Flags.NeverAuto || tk.Subject.SecretTo == "" || len(tk.Subject.Inputs) != 2 ||
		tk.Subject.Inputs[0] != "dest" || tk.Subject.Inputs[1] != "src" || tk.Subject.Verb != "move" {
		t.Fatalf("pushed: %+v %+v", tk.Flags, tk.Subject)
	}
	if subj.SecretTo != "" || subj.Inputs != nil {
		t.Fatalf("the product's subject was changed: %+v", subj)
	}
	if h.Store.InputKey(d.Screen.Hub.PlanID, pend.Ticket) == nil {
		t.Fatal("no key kept for the ticket")
	}
	// A read without a subject gets one.
	r := inputsDecisionFor(t, h, ticket.KindRead, nil, "needle")
	r.Screen.Hub.Risk = ticket.RiskRead
	pend, err = a.Submit(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if tk, err = ticket.VerifyTicket(lockPub, hub.Ticket(pend.Ticket)); err != nil || tk.Subject == nil || tk.Subject.Inputs[0] != "needle" {
		t.Fatalf("read: %+v %v", tk, err)
	}
	// Inputs on any other kind, or on no kind, are refused before a push.
	pushed := hub.Pushed()
	for _, k := range []ticket.Kind{"", ticket.KindWrite, ticket.KindDDL} {
		if _, err := a.Submit(ctx, inputsDecisionFor(t, h, k, nil, "x")); !errors.Is(err, errInputsKind) {
			t.Errorf("kind %q: %v", k, err)
		}
	}
	if hub.Pushed() != pushed {
		t.Fatal("a refused ticket was pushed")
	}
}
