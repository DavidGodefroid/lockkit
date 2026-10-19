//go:build unix

package console

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/ipc"
)

// piiPolicy is fakePolicy with mask and allow rules.
type piiPolicy struct {
	fakePolicy
	Mask  []string `json:"mask"`
	Allow []string `json:"allow"`
}

func (p piiPolicy) Diff(approved config.Policy) []config.Change {
	a := approved.(piiPolicy)
	out := p.fakePolicy.Diff(a.fakePolicy)
	out = append(out, config.SetDiff("pii.mask", a.Mask, p.Mask, true)...)
	return append(out, config.SetDiff("pii.allow", a.Allow, p.Allow, false)...)
}

// piiBackend keeps its "file" in memory: saved is what SaveMask wrote.
type piiBackend struct {
	fakeBackend
	mu      sync.Mutex
	pol     piiPolicy
	saved   []string
	saveErr error
}

func (b *piiBackend) LoadPolicy() (Policy, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pol, nil
}

func (b *piiBackend) PIIRules(p Policy) (mask, allow []string) {
	q := p.(piiPolicy)
	return q.Mask, q.Allow
}

func (b *piiBackend) CheckMask(pattern string) (string, error) {
	if strings.Count(pattern, ".") != 1 {
		return "", errors.New("want queue.field")
	}
	return strings.ToLower(pattern), nil
}

func (b *piiBackend) SaveMask(pattern string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.saveErr != nil {
		return b.saveErr
	}
	b.saved = append(b.saved, pattern)
	return nil
}

func (b *piiBackend) WithMask(p Policy, pattern string) Policy {
	q := p.(piiPolicy)
	q.Mask = config.SortedSet(append(slices.Clone(q.Mask), pattern))
	return q
}

func newPIIHarness(t *testing.T, p piiPolicy) (*harness, *piiBackend) {
	t.Helper()
	b := &piiBackend{pol: p}
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Backend, c.Policy = b, p })
	return h, b
}

func piiUAT() piiPolicy { return piiPolicy{fakePolicy: uat(), Mask: []string{"orders.email"}, Allow: []string{"orders.id"}} }

func TestPIIListAndAdd(t *testing.T) {
	h, b := newPIIHarness(t, piiUAT())
	var list ipc.PIIListResult
	r := h.call(t, context.Background(), ipc.MethodPIIList, nil)
	if r.Error != nil || json.Unmarshal(r.Result, &list) != nil || !slices.Equal(list.Mask, []string{"orders.email"}) || !slices.Equal(list.Allow, []string{"orders.id"}) {
		t.Fatalf("pii.list: %+v", r)
	}

	r = h.call(t, context.Background(), ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "Orders.Phone"})
	if r.Error != nil || json.Unmarshal(r.Result, &list) != nil || !slices.Equal(list.Mask, []string{"orders.email", "orders.phone"}) {
		t.Fatalf("pii.add: %+v", r)
	}
	if !slices.Equal(b.saved, []string{"orders.phone"}) {
		t.Fatalf("saved to the file: %v", b.saved)
	}
	if got := h.s.Policy().(piiPolicy).Mask; !slices.Equal(got, []string{"orders.email", "orders.phone"}) {
		t.Fatalf("policy in force: %v", got)
	}
	if !strings.Contains(h.io.plain(), "PII rule added by a client: mask orders.phone") {
		t.Fatalf("console line missing: %s", h.io.plain())
	}
	if rec := h.lastRecord(t); rec["event"] != "policy" || rec["decision"] != "tightened" {
		t.Fatalf("audit: %v", rec)
	}
	// The approved store holds the tightened policy: a restart keeps it.
	var stored piiPolicy
	if ok, err := config.LoadApproved(testProduct, h.state, "user-uat", &stored); !ok || err != nil || !slices.Contains(stored.Mask, "orders.phone") {
		t.Fatalf("approved store: %v %v %+v", ok, err, stored)
	}
}

func TestPIIAddRefusals(t *testing.T) {
	h, b := newPIIHarness(t, piiUAT())
	if r := h.call(t, context.Background(), ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "nodot"}); r.Error == nil || r.Error.Code != ipc.CodeInvalidParams {
		t.Fatalf("bad pattern: %+v", r)
	}
	if r := h.call(t, context.Background(), ipc.MethodPIIAdd, map[string]string{"column": "a.b"}); r.Error == nil || r.Error.Code != ipc.CodeInvalidParams {
		t.Fatalf("unknown field: %+v", r)
	}
	b.saveErr = errors.New("disk full")
	if r := h.call(t, context.Background(), ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "orders.phone"}); r.Error == nil || r.Error.Code != ipc.CodeInternal {
		t.Fatalf("save error: %+v", r)
	}
	if got := h.s.Policy().(piiPolicy).Mask; !slices.Equal(got, []string{"orders.email"}) {
		t.Fatalf("policy changed after a failed save: %v", got)
	}
}

// A loosening read before the rule reached the file must not drop the rule
// once the human applies it from :review.
func TestPIIAddKeepsRuleInPendingLoosening(t *testing.T) {
	h, b := newPIIHarness(t, piiUAT())
	loose := piiUAT()
	loose.Tier = "peek"
	b.pol = loose
	h.s.CheckPolicy()
	if !h.s.PolicyPending() {
		t.Fatal("loosening not pending")
	}
	if r := h.call(t, context.Background(), ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "orders.phone"}); r.Error != nil {
		t.Fatalf("pii.add: %+v", r)
	}
	if got := (*h.s.pending).(piiPolicy).Mask; !slices.Contains(got, "orders.phone") {
		t.Fatalf("pending loosening lost the rule: %v", got)
	}
}

func TestPIIMethodsWithoutPIIBackend(t *testing.T) {
	h := newHarness(t, uat(), nil)
	for _, m := range []string{ipc.MethodPIIList, ipc.MethodPIIAdd} {
		r := h.call(t, context.Background(), m, nil)
		if r.Error == nil || r.Error.Code != ipc.CodeMethodNotFound || !strings.Contains(r.Error.Message, "no PII rules") {
			t.Fatalf("%s: %+v", m, r)
		}
	}
}

type piiServingBackend struct{ fakeBackend }

func (*piiServingBackend) Methods() map[string]Handler {
	return map[string]Handler{ipc.MethodPIIAdd: func(context.Context, ipc.Request, Env) ipc.Response { return ipc.Response{} }}
}

func TestNewServerRefusesTakingPIIMethods(t *testing.T) {
	h := newHarness(t, uat(), nil)
	if _, err := NewServer(ServerConfig{Product: testProduct, Backend: &piiServingBackend{}, Policy: uat(), Audit: h.s.cfg.Audit, IO: &fakeIO{}}); err == nil {
		t.Fatal("a backend serving pii.add accepted")
	}
}
