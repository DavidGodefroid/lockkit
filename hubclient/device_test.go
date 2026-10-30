package hubclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"
	"github.com/DavidGodefroid/lockkit/ticket/devicetest"
)

const (
	rpID   = "hub.example.net"
	origin = "https://hub.example.net"
)

// onDevice signs the decision on a as the phone would, once the hub has
// filled in its fields (the hub key id is part of what the device signs).
func onDevice(e *env, a *devicetest.Authenticator) func(*ticket.Decision) {
	return func(d *ticket.Decision) {
		d.HubKeyID = ticket.KeyID(e.hub.Pub)
		a.Decide(d)
	}
}

func withDevices(devs ...ticket.Device) func(*hubclient.Config) {
	return func(c *hubclient.Config) { c.Devices = devs }
}

func TestDeviceDecisionRuns(t *testing.T) {
	phone := devicetest.New(rpID, origin, "phone")
	e := newEnv(t, withDevices(phone.Device()))
	p, id := submitted(t, e)
	e.hub.DecideWith(id, ticket.Approved, "", nil, onDevice(e, phone))
	if n, err := e.client.Poll(context.Background(), 0); err != nil || n != 1 {
		t.Fatalf("poll: %d %v", n, err)
	}
	got, d, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash))
	if err != nil || got.ID != p.ID || d.Device == nil || d.Facade != ticket.FacadeMobile {
		t.Fatalf("begin: %+v %+v %v", got, d, err)
	}
	// Replayed: the plan ran, its nonce is spent.
	e.hub.DecideWith(id, ticket.Approved, "", nil, onDevice(e, phone))
	e.client.Poll(context.Background(), 0)
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); err == nil {
		t.Fatal("a replayed device approval ran again")
	}
}

// What a compromised hub can do with its own key: none of it passes for a
// decision taken on the device.
func TestCompromisedHubCannotForgeDeviceDecision(t *testing.T) {
	phone := devicetest.New(rpID, origin, "phone")
	cases := map[string]func(e *env) func(*ticket.Decision){
		"mobile facade, no device signature": func(e *env) func(*ticket.Decision) {
			return func(d *ticket.Decision) { d.Facade, d.Approver.ID = ticket.FacadeMobile, ticket.DeviceID(phone.Cred) }
		},
		"device signature of the hub's own key": func(e *env) func(*ticket.Decision) {
			fake := devicetest.New(rpID, origin, "phone")
			fake.Cred = phone.Cred
			return onDevice(e, fake)
		},
		"unpinned device": func(e *env) func(*ticket.Decision) {
			return onDevice(e, devicetest.New(rpID, origin, "stranger"))
		},
		"device signature moved to another nonce": func(e *env) func(*ticket.Decision) {
			return func(d *ticket.Decision) {
				onDevice(e, phone)(d)
				d.Nonce = ticket.NewNonce()
			}
		},
		"device denial turned approval": func(e *env) func(*ticket.Decision) {
			return func(d *ticket.Decision) {
				d.Decision = ticket.Denied
				onDevice(e, phone)(d)
				d.Decision = ticket.Approved
			}
		},
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, withDevices(phone.Device()))
			p, id := submitted(t, e)
			e.hub.DecideWith(id, ticket.Approved, "", nil, mod(e))
			n, err := e.client.Poll(context.Background(), 0)
			if n != 0 || !errors.Is(err, hubclient.ErrBadDecision) {
				t.Fatalf("poll: %d %v, want the decision dropped", n, err)
			}
			if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, hubclient.ErrPending) {
				t.Fatalf("begin: %v, want ErrPending", err)
			}
			if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Pending {
				t.Fatalf("plan is %s", sp.State)
			}
		})
	}
}

func TestDeviceDecisionOfAnotherInstanceRefused(t *testing.T) {
	phone := devicetest.New(rpID, origin, "phone")
	e := newEnv(t, withDevices(phone.Device()))
	_, id := submitted(t, e)
	e.hub.DecideWith(id, ticket.Approved, "", nil, func(d *ticket.Decision) {
		d.Instance = "billing" // signed by the device for billing
		onDevice(e, phone)(d)
	})
	if n, err := e.client.Poll(context.Background(), 0); n != 0 || !errors.Is(err, hubclient.ErrBadDecision) {
		t.Fatalf("poll: %d %v", n, err)
	}
}

func TestNoPinnedDeviceRefusesMobileDecisions(t *testing.T) {
	phone := devicetest.New(rpID, origin, "phone")
	e := newEnv(t, nil)
	_, id := submitted(t, e)
	e.hub.DecideWith(id, ticket.Approved, "", nil, onDevice(e, phone))
	if n, err := e.client.Poll(context.Background(), 0); n != 0 || !errors.Is(err, hubclient.ErrBadDecision) {
		t.Fatalf("poll: %d %v", n, err)
	}
}

func TestRequireDevice(t *testing.T) {
	phone := devicetest.New(rpID, origin, "phone")
	cfg := func(c *hubclient.Config) {
		c.Devices = []ticket.Device{phone.Device()}
		c.RequireDevice = []ticket.Risk{ticket.RiskWrite}
	}
	// A terminal approval of a write: the hub alone vouches for it.
	e := newEnv(t, cfg)
	p, id := submitted(t, e)
	e.hub.Decide(id, ticket.Approved, "")
	if _, err := e.client.Poll(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, ticket.ErrDevice) {
		t.Fatalf("tty approval of a device-only risk: %v", err)
	}
	if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Denied {
		t.Fatalf("plan is %s, want denied", sp.State)
	}
	// The same on the device runs.
	e = newEnv(t, cfg)
	_, id = submitted(t, e)
	e.hub.DecideWith(id, ticket.Approved, "", nil, onDevice(e, phone))
	e.client.Poll(context.Background(), 0)
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); err != nil {
		t.Fatal(err)
	}
	if _, err := hubclient.New(hubclient.Config{URL: "http://127.0.0.1:1", Instance: inst, Key: e.cfg.Key, HubKey: e.hub.Pub,
		StateFile: "s", RequireDevice: []ticket.Risk{ticket.RiskWrite}}); err == nil {
		t.Fatal("RequireDevice without devices accepted")
	}
}

func TestSubmitClearSealsToDevices(t *testing.T) {
	phone := devicetest.New(rpID, origin, "phone")
	tablet := devicetest.New(rpID, origin, "tablet")
	e := newEnv(t, withDevices(phone.Device(), tablet.Device()))
	p, tk := e.plan(t, planHash)
	clear := &ticket.Screen{Header: "db / crm · write", Body: []string{"UPDATE customers SET email = 'jane.doe@example.com'"}}
	id, err := e.client.SubmitClear(context.Background(), e.store, p.ID, caller, tk, screen(), clear)
	if err != nil {
		t.Fatal(err)
	}
	raw := e.hub.Ticket(id)
	if strings.Contains(string(raw), "jane.doe") {
		t.Fatal("clear value reached the hub")
	}
	var got ticket.Ticket
	if err := json.Unmarshal(raw, &got); err != nil || len(got.PII.SealedFor) != 2 {
		t.Fatalf("sealed_for: %+v %v", got.PII, err)
	}
	for _, a := range []*devicetest.Authenticator{phone, tablet} {
		var box *ticket.DeviceBox
		for i := range got.PII.SealedFor {
			if got.PII.SealedFor[i].Device == ticket.DeviceID(a.Cred) {
				box = &got.PII.SealedFor[i]
			}
		}
		s, err := ticket.OpenClearScreen(a.Seal, id, box)
		if err != nil || s.Body[0] != clear.Body[0] {
			t.Fatalf("%s: %+v %v", a.Name, s, err)
		}
	}
	// Without devices nothing is sealed.
	e = newEnv(t, nil)
	p, tk = e.plan(t, planHash)
	id, _ = e.client.SubmitClear(context.Background(), e.store, p.ID, caller, tk, screen(), clear)
	if strings.Contains(string(e.hub.Ticket(id)), "sealed_for") {
		t.Fatal("sealed without devices")
	}
}
