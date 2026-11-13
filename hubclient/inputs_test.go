package hubclient_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// needle is the value the human types in these tests: it must reach the
// run, and nothing else.
const needle = "alice@example.org"

// inputsPlan makes a plan and its read ticket asking for the values
// named names.
func (e *env) inputsPlan(t *testing.T, names ...string) (*plans.Plan, *ticket.Ticket) {
	t.Helper()
	p, _ := e.plan(t, planHash)
	tk := ticket.NewKindTicket(ticket.Source{Lock: "locksql"}, ticket.KindRead, ticket.RiskReadPII,
		&ticket.Subject{Profile: "crm-prod", Target: "customers", Inputs: names}, planHash, policyFP, time.Now(), time.Hour)
	tk.Workspace, tk.Requester = "~/Documents", ticket.Requester{Agent: "dev-1", Session: "s1"}
	return p, tk
}

// sealedApproval approves ticket id as the decider does: it verifies the
// ticket under the lock key it pins, then seals values to it.
func (e *env) sealedApproval(t *testing.T, id string, values map[string][]byte) {
	t.Helper()
	tk, err := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(id))
	if err != nil {
		t.Fatal(err)
	}
	box, err := ticket.SealInputs(tk, values)
	if err != nil {
		t.Fatal(err)
	}
	e.hub.DecideWith(id, ticket.Approved, "", nil, func(d *ticket.Decision) { d.Secret = box })
}

// grepTree fails when any file under dir holds one of needles.
func grepTree(t *testing.T, dir string, needles ...[]byte) {
	t.Helper()
	err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, n := range needles {
			if bytes.Contains(b, n) {
				t.Errorf("%s holds %q", path, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestInputsEndToEnd(t *testing.T) {
	ctx := context.Background()
	storeDir := t.TempDir()
	e := newEnv(t, nil)
	st, err := plans.Open(filepath.Join(storeDir, "plans"))
	if err != nil {
		t.Fatal(err)
	}
	e.store = st
	p, tk := e.inputsPlan(t, "needle")
	id, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	if err != nil {
		t.Fatal(err)
	}
	// Pushed with its one-use key, never auto.
	pushed, err := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(id))
	if err != nil {
		t.Fatal(err)
	}
	if !pushed.Flags.NeverAuto || pushed.Subject.SecretTo == "" || len(pushed.Subject.Inputs) != 1 || pushed.Subject.Inputs[0] != "needle" {
		t.Fatalf("pushed: flags %+v subject %+v", pushed.Flags, pushed.Subject)
	}
	key := e.store.InputKey(p.ID, id)
	if key == nil || ticket.EncodeX25519(key.PublicKey()) != pushed.Subject.SecretTo {
		t.Fatal("the store keeps no key for the ticket's secret_to")
	}
	// The private key is in memory only.
	raw := key.Bytes()
	grepTree(t, storeDir, raw, []byte(base64.RawURLEncoding.EncodeToString(raw)), []byte(base64.StdEncoding.EncodeToString(raw)))
	grepTree(t, filepath.Dir(e.cfg.StateFile), raw, []byte(base64.RawURLEncoding.EncodeToString(raw)))

	e.sealedApproval(t, id, map[string][]byte{"needle": []byte(needle)})
	if n, err := e.client.Poll(ctx, 0); err != nil || n != 1 {
		t.Fatalf("poll: %d %v", n, err)
	}
	run, d, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash))
	if err != nil {
		t.Fatal(err)
	}
	if run.State != plans.Executing || string(run.Inputs["needle"]) != needle || len(run.Inputs) != 1 {
		t.Fatalf("run: %s %q", run.State, run.Inputs)
	}
	if e.store.InputKey(p.ID, id) != nil {
		t.Fatal("the key outlives the run")
	}
	// The product audits the names, never the values.
	stateDir := t.TempDir()
	lg, err := audit.Open(kit.Product{Name: "locksql"}, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := lg.Append(audit.Base{Event: audit.EventApproved, Decision: "approved", Ticket: id, Approver: &d.Approver,
		Facade: d.Facade, HubSig: d.Sig, Inputs: audit.InputNames(run.Inputs)}); err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile(lg.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(log, []byte(`"inputs":["needle"]`)) {
		t.Fatalf("audit names no input: %s", log)
	}
	if err := e.client.Finish(ctx, e.store, p.ID, caller, true, ""); err != nil {
		t.Fatal(err)
	}
	// The value is in neither the hub's ticket and decision, nor the
	// audit, nor the lock's files.
	for _, b := range append(e.hub.Decisions(), e.hub.Ticket(id)) {
		if bytes.Contains(b, []byte(needle)) {
			t.Fatalf("the hub holds the value: %s", b)
		}
	}
	grepTree(t, stateDir, []byte(needle))
	grepTree(t, storeDir, []byte(needle))
	grepTree(t, filepath.Dir(e.cfg.StateFile), []byte(needle))
}

func TestInputsRefusedDecisions(t *testing.T) {
	ctx := context.Background()
	for name, decide := range map[string]func(e *env, id string){
		"no box": func(e *env, id string) { e.hub.Decide(id, ticket.Approved, "") },
		"connect secret box": func(e *env, id string) {
			tk, _ := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(id))
			raw, _ := base64.RawURLEncoding.DecodeString(tk.Subject.SecretTo)
			pub, err := ecdh.X25519().NewPublicKey(raw)
			if err != nil {
				t.Fatal(err)
			}
			box, err := ticket.Seal(pub, []byte(`{"needle":"x"}`), ticket.SecretAAD(tk))
			if err != nil {
				t.Fatal(err)
			}
			e.hub.DecideWith(id, ticket.Approved, "", nil, func(d *ticket.Decision) { d.Secret = box })
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			p, tk := e.inputsPlan(t, "needle")
			id, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
			if err != nil {
				t.Fatal(err)
			}
			decide(e, id)
			if _, err := e.client.Poll(ctx, 0); err != nil {
				t.Fatal(err)
			}
			run, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash))
			if !errors.Is(err, hubclient.ErrBadDecision) || run != nil {
				t.Fatalf("begin: %v", err)
			}
			if sp, _ := e.store.Get(p.ID, caller); sp.State != plans.Denied {
				t.Fatalf("plan is %s", sp.State)
			}
		})
	}
	t.Run("auto rule", func(t *testing.T) {
		e := newEnv(t, nil)
		e.hub.AutoDecide("read-all")
		p, tk := e.inputsPlan(t, "needle")
		id, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.client.Poll(ctx, 0); err != nil {
			t.Fatal(err)
		}
		if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, ticket.ErrAuto) {
			t.Fatalf("begin: %v", err)
		}
	})
}

func TestInputsAfterRestartRenew(t *testing.T) {
	ctx := context.Background()
	storeDir := filepath.Join(t.TempDir(), "plans")
	e := newEnv(t, nil)
	st, err := plans.Open(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	e.store = st
	p, tk := e.inputsPlan(t, "needle")
	id, err := e.client.Submit(ctx, e.store, p.ID, caller, tk, screen())
	if err != nil {
		t.Fatal(err)
	}
	first, _ := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(id))
	// The lock restarts: its store and client come back from disk, the
	// key does not.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if e.store, err = plans.Open(storeDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.store.Close() })
	if e.client, err = hubclient.New(e.cfg); err != nil {
		t.Fatal(err)
	}
	e.sealedApproval(t, id, map[string][]byte{"needle": []byte(needle)})
	if _, err := e.client.Poll(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.client.Begin(e.store, id, caller, recheck(policyFP, planHash)); !errors.Is(err, ticket.ErrExpired) {
		t.Fatalf("begin after restart: %v", err)
	}
	// Renewed, the new ticket has a key of its own, and runs.
	n, err := e.client.Renew(ctx, e.store, id, caller)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := ticket.VerifyTicket(e.lockPub, e.hub.Ticket(n))
	if err != nil {
		t.Fatal(err)
	}
	if renewed.Subject.SecretTo == "" || renewed.Subject.SecretTo == first.Subject.SecretTo || !renewed.Flags.NeverAuto {
		t.Fatalf("renewal: %+v %+v", renewed.Subject, renewed.Flags)
	}
	e.sealedApproval(t, n, map[string][]byte{"needle": []byte(needle)})
	if _, err := e.client.Poll(ctx, 0); err != nil {
		t.Fatal(err)
	}
	run, _, err := e.client.Begin(e.store, n, caller, recheck(policyFP, planHash))
	if err != nil {
		t.Fatal(err)
	}
	if string(run.Inputs["needle"]) != needle {
		t.Fatalf("run: %q", run.Inputs)
	}
}
