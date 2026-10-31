//go:build unix

package console

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// WithdrawStandalone is inert: the pending plan of a hub instance whose
// console is stopped (its store not locked) stays pending, and nothing is
// written.
func TestWithdrawStandaloneIsInert(t *testing.T) {
	state := t.TempDir()
	dir := filepath.Join(state, testProduct.Name, "hub", hubInstance, "plans")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := plans.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.Create(plans.Binding{UID: hubCaller.UID, Agent: "dev-1", TokenHash: plans.HashToken(hubCaller.Token),
		PolicyFP: hubPolicyFP, PlanHash: hubPlanHash}, json.RawMessage(`{}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	tk := ticket.NewTicket(ticket.Source{Lock: testProduct.Name, Instance: hubInstance}, ticket.RiskWrite, hubPlanHash, hubPolicyFP, time.Now(), 0)
	_, key, _ := ed25519.GenerateKey(nil)
	if err := tk.Sign(key); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkPending(p.ID, hubCaller, tk); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadDir(dir)

	ws, err := WithdrawStandalone(testProduct, state)
	if ws != nil || err != nil {
		t.Fatalf("WithdrawStandalone: %v %v", ws, err)
	}
	if after, _ := os.ReadDir(dir); len(after) != len(before) {
		t.Fatalf("files %d → %d", len(before), len(after))
	}
	st, err = plans.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if pend := st.Pending(); len(pend) != 1 || pend[0].ID != p.ID || len(st.Untold()) != 0 {
		t.Fatalf("pending %v untold %v", pend, st.Untold())
	}
}
