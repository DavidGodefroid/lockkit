package hubclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"
)

func connectTicket(t *testing.T) *ticket.Ticket {
	t.Helper()
	tk, err := ticket.NewConnectTicket(ticket.Source{Lock: "locksql"}, ticket.RiskRead,
		ticket.Subject{Profile: "crm", Endpoint: "db:5432", Credential: ticket.CredentialKeychain}, policyFP, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

// decideFirst decides the first ticket the hub gets, with mod.
func decideFirst(e *env, out ticket.Outcome, key ed25519.PrivateKey, mod func(*ticket.Decision)) {
	go func() {
		for range 2000 {
			if ids := e.hub.Tickets(); len(ids) > 0 {
				e.hub.DecideWith(ids[0], out, "because", key, mod)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
}

func TestAskConnect(t *testing.T) {
	e := newEnv(t, nil)
	tk := connectTicket(t)
	decideFirst(e, ticket.Approved, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := e.client.Ask(ctx, tk, screen())
	if err != nil {
		t.Fatal(err)
	}
	if d.Decision != ticket.Approved || d.V != ticket.VersionKinds || d.Rule == nil || d.Match(tk) != nil {
		t.Fatalf("decision %+v", d)
	}
	// The pushed ticket is signed by the lock and masked.
	got, err := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(tk.ID))
	if err != nil || got.Source.Instance != inst || strings.Contains(strings.Join(got.Screen.Body, ""), "jane.doe") {
		t.Fatalf("pushed %v %+v", err, got)
	}
	if err := e.client.Consumed(ctx, tk.ID); err != nil || !e.hub.Consumed(tk.ID) {
		t.Fatalf("consumed: %v", err)
	}
}

func TestAskReturnsDenial(t *testing.T) {
	e := newEnv(t, nil)
	tk := connectTicket(t)
	decideFirst(e, ticket.Denied, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := e.client.Ask(ctx, tk, screen())
	if err != nil || d.Decision != ticket.Denied || d.Reason != "because" {
		t.Fatalf("denial: %+v %v", d, err)
	}
}

func TestAskRefuses(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	if _, err := e.client.Ask(ctx, connectTicket(t), render.MaskedScreen{}); !errors.Is(err, render.ErrUnmasked) {
		t.Fatalf("unmasked: %v", err)
	}
	_, w := e.plan(t, planHash)
	if _, err := e.client.Ask(ctx, w, screen()); err == nil {
		t.Fatal("a write ticket through Ask")
	}
	if e.hub.Pushed() != 0 {
		t.Fatal("pushed")
	}
}

// A decision the hub signs with another key, or that names another plan,
// is not taken; Ask waits on until its context ends.
func TestAskIgnoresForgedDecision(t *testing.T) {
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for name, c := range map[string]struct {
		key ed25519.PrivateKey
		mod func(*ticket.Decision)
	}{
		"other key":  {other, nil},
		"other plan": {nil, func(d *ticket.Decision) { d.PlanHash = planHash }},
		"v1 answer":  {nil, func(d *ticket.Decision) { d.V, d.Rule = ticket.Version, nil }},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			decideFirst(e, ticket.Approved, c.key, c.mod)
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			d, err := e.client.Ask(ctx, connectTicket(t), screen())
			if err == nil {
				t.Fatalf("took %+v", d)
			}
			if !errors.Is(err, hubclient.ErrBadDecision) && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error %v", err)
			}
		})
	}
}

func TestAskRateLimited(t *testing.T) {
	e := newEnv(t, func(c *hubclient.Config) { c.RateN = 1 })
	decideFirst(e, ticket.Approved, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := e.client.Ask(ctx, connectTicket(t), screen()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.Ask(ctx, connectTicket(t), screen()); !errors.Is(err, hubclient.ErrRateLimited) {
		t.Fatalf("rate: %v", err)
	}
}
