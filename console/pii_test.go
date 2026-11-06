//go:build unix

package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
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

func piiUAT() piiPolicy {
	return piiPolicy{fakePolicy: uat(), Mask: []string{"orders.email"}, Allow: []string{"orders.id"}}
}

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

// peerCtx is the context of a request from the client (uid, pid).
func peerCtx(uid, pid int) context.Context {
	return WithPeer(context.Background(), ipc.Cred{UID: uid, GID: uid, PID: pid})
}

// pii.add is audited with the client behind it and the pattern it added:
// it is told apart from a tightening the human made in the files.
func TestPIIAddAuditsPeerAndPattern(t *testing.T) {
	h, _ := newPIIHarness(t, piiUAT())
	uid := os.Getuid()
	if r := h.call(t, peerCtx(uid, 4242), ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "Orders.Phone"}); r.Error != nil {
		t.Fatalf("pii.add: %+v", r)
	}
	rec := h.lastRecord(t)
	if rec["event"] != "policy" || rec["decision"] != "tightened" || rec["profile"] != "uat" {
		t.Fatalf("audit: %v", rec)
	}
	// The pattern as the product checked it, not as the client typed it.
	if rec["pattern"] != "orders.phone" {
		t.Fatalf("pattern: %v", rec)
	}
	if rec["peer_uid"] != float64(uid) || rec["peer_pid"] != float64(4242) {
		t.Fatalf("peer: %v", rec)
	}
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && rec["peer_user"] != u.Username {
		t.Fatalf("peer user: %v, want %s", rec, u.Username)
	}
}

// A tightening read from the files carries neither a client nor a pattern.
func TestFileTighteningAuditedWithoutPeerOrPattern(t *testing.T) {
	h, b := newPIIHarness(t, piiUAT())
	tighter := piiUAT()
	tighter.Mask = []string{"orders.email", "orders.phone"}
	b.mu.Lock()
	b.pol = tighter
	b.mu.Unlock()
	h.s.CheckPolicy()
	rec := h.lastRecord(t)
	if rec["event"] != "policy" || rec["decision"] != "tightened" {
		t.Fatalf("audit: %v", rec)
	}
	for _, k := range []string{"pattern", "peer_uid", "peer_pid", "peer_user"} {
		if _, ok := rec[k]; ok {
			t.Fatalf("a file tightening recorded %s: %v", k, rec)
		}
	}
}

// piiRefuser is a piiBackend whose ApplyPolicy refuses every policy once
// refuse is set.
type piiRefuser struct {
	piiBackend
	refuse bool
}

func (b *piiRefuser) ApplyPolicy(Policy) error {
	if b.refuse {
		return errors.New("cannot enforce")
	}
	return nil
}

// A pii.add the backend cannot enforce is audited as failed, with the
// client and the pattern too.
func TestPIIAddFailureAuditsPeerAndPattern(t *testing.T) {
	b := &piiRefuser{piiBackend: piiBackend{pol: piiUAT()}}
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Backend, c.Policy = b, piiUAT() })
	b.refuse = true
	uid := os.Getuid()
	if r := h.call(t, peerCtx(uid, 77), ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "orders.phone"}); r.Error == nil {
		t.Fatalf("pii.add answered ok: %+v", r)
	}
	rec := h.lastRecord(t)
	if rec["decision"] != "failed" || !strings.Contains(fmt.Sprint(rec["error"]), "tightening refused by the backend") {
		t.Fatalf("audit: %v", rec)
	}
	if rec["pattern"] != "orders.phone" || rec["peer_uid"] != float64(uid) || rec["peer_pid"] != float64(77) {
		t.Fatalf("failed record without the client or the pattern: %v", rec)
	}
}

// End to end over the socket: the record carries the kernel's credentials
// of the real client (this process) and the pattern.
func TestPIIAddOverSocketAuditsKernelPeer(t *testing.T) {
	h, _ := newPIIHarness(t, piiUAT())
	d, err := os.MkdirTemp("/tmp", "lkpii")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	socket := filepath.Join(d, "s")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- h.s.Loop().Serve(ctx, ln, nil) }()
	r := dialAndCall(t, socket, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "orders.phone"})
	cancel()
	<-served
	if r.Error != nil {
		t.Fatalf("pii.add: %+v", r.Error)
	}
	var rec map[string]any
	for _, x := range h.records(t) {
		if x["event"] == "policy" && x["decision"] == "tightened" {
			rec = x
		}
	}
	if rec == nil {
		t.Fatalf("no tightened record: %v", h.records(t))
	}
	if rec["pattern"] != "orders.phone" || rec["peer_uid"] != float64(os.Getuid()) {
		t.Fatalf("record: %v", rec)
	}
	// Linux and the BSDs give the client's pid; where the kernel does not,
	// none is recorded.
	if pid, ok := rec["peer_pid"]; ok && pid != float64(os.Getpid()) {
		t.Fatalf("peer pid %v, want %d", pid, os.Getpid())
	}
}

// piiLeakyBackend is a piiBackend whose CheckMask error quotes the
// pattern, as a product's "unknown column X" would.
type piiLeakyBackend struct{ piiBackend }

func (b *piiLeakyBackend) CheckMask(pattern string) (string, error) {
	if _, err := b.piiBackend.CheckMask(pattern); err != nil {
		return "", fmt.Errorf("unknown column %q", pattern)
	}
	return strings.ToLower(pattern), nil
}

// A pii.add refused by CheckMask leaves one policy/failed record with the
// client, and neither the raw pattern nor the backend's text quoting it.
func TestPIIAddCheckMaskRefusalAuditedWithPeer(t *testing.T) {
	b := &piiLeakyBackend{piiBackend: piiBackend{pol: piiUAT()}}
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Backend, c.Policy = b, piiUAT() })
	before := countRecords(t, h)
	uid := os.Getuid()
	r := h.call(t, peerCtx(uid, 91), ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "JohnSmithSecret"})
	if r.Error == nil || r.Error.Code != ipc.CodeInvalidParams {
		t.Fatalf("bad pattern: %+v", r)
	}
	recs := h.records(t)
	if len(recs) != before+1 {
		t.Fatalf("want one record, got %d: %v", len(recs)-before, recs[before:])
	}
	rec := recs[len(recs)-1]
	if rec["event"] != "policy" || rec["decision"] != "failed" || rec["error"] != piiAddInvalid || rec["profile"] != "uat" {
		t.Fatalf("audit: %v", rec)
	}
	if rec["peer_uid"] != float64(uid) || rec["peer_pid"] != float64(91) {
		t.Fatalf("peer: %v", rec)
	}
	if _, ok := rec["pattern"]; ok {
		t.Fatalf("refused pattern recorded: %v", rec)
	}
	if raw, _ := json.Marshal(rec); strings.Contains(strings.ToLower(string(raw)), "johnsmithsecret") {
		t.Fatalf("raw pattern in the audit log: %s", raw)
	}
}

// A pii.add refused by SaveMask leaves one policy/failed record with the
// client, the canonical pattern and the error.
func TestPIIAddSaveMaskRefusalAuditedWithPeer(t *testing.T) {
	h, b := newPIIHarness(t, piiUAT())
	b.saveErr = errors.New("rule cap reached")
	before := countRecords(t, h)
	uid := os.Getuid()
	r := h.call(t, peerCtx(uid, 92), ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "Orders.Phone"})
	if r.Error == nil || r.Error.Code != ipc.CodeInternal {
		t.Fatalf("save error: %+v", r)
	}
	recs := h.records(t)
	if len(recs) != before+1 {
		t.Fatalf("want one record, got %d: %v", len(recs)-before, recs[before:])
	}
	rec := recs[len(recs)-1]
	if rec["event"] != "policy" || rec["decision"] != "failed" || !strings.HasPrefix(fmt.Sprint(rec["error"]), piiAddUnsaved) || !strings.Contains(fmt.Sprint(rec["error"]), "rule cap reached") {
		t.Fatalf("audit: %v", rec)
	}
	if rec["pattern"] != "orders.phone" || rec["peer_uid"] != float64(uid) || rec["peer_pid"] != float64(92) {
		t.Fatalf("record without the client or the canonical pattern: %v", rec)
	}
}

// End to end over the socket: both refusals of the backend are audited
// with the kernel's credentials of the real client, before any other call.
func TestPIIAddRefusalsOverSocketAuditKernelPeer(t *testing.T) {
	b := &piiLeakyBackend{piiBackend: piiBackend{pol: piiUAT()}}
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Backend, c.Policy = b, piiUAT() })
	d, err := os.MkdirTemp("/tmp", "lkpiir")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	socket := filepath.Join(d, "s")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- h.s.Loop().Serve(ctx, ln, nil) }()
	r1 := dialAndCall(t, socket, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "JohnSmithSecret"})
	b.mu.Lock()
	b.saveErr = errors.New("rule cap reached")
	b.mu.Unlock()
	r2 := dialAndCall(t, socket, ipc.MethodPIIAdd, ipc.PIIAddParams{Pattern: "orders.phone"})
	cancel()
	<-served
	if r1.Error == nil || r1.Error.Code != ipc.CodeInvalidParams || r2.Error == nil || r2.Error.Code != ipc.CodeInternal {
		t.Fatalf("answers: %+v %+v", r1.Error, r2.Error)
	}
	var failed []map[string]any
	for _, x := range h.records(t) {
		if x["event"] == "policy" && x["decision"] == "failed" {
			failed = append(failed, x)
		}
	}
	if len(failed) != 2 {
		t.Fatalf("want 2 failed records: %v", h.records(t))
	}
	for i, rec := range failed {
		if rec["peer_uid"] != float64(os.Getuid()) {
			t.Fatalf("record %d without the kernel peer: %v", i, rec)
		}
		if pid, ok := rec["peer_pid"]; ok && pid != float64(os.Getpid()) {
			t.Fatalf("peer pid %v, want %d", pid, os.Getpid())
		}
	}
	if _, ok := failed[0]["pattern"]; ok || failed[0]["error"] != piiAddInvalid {
		t.Fatalf("CheckMask refusal: %v", failed[0])
	}
	if failed[1]["pattern"] != "orders.phone" || !strings.HasPrefix(fmt.Sprint(failed[1]["error"]), piiAddUnsaved) {
		t.Fatalf("SaveMask refusal: %v", failed[1])
	}
	raw, err := os.ReadFile(h.log)
	if err == nil && strings.Contains(strings.ToLower(string(raw)), "johnsmithsecret") {
		t.Fatal("raw pattern in the audit log")
	}
}

// countRecords is the number of records in h's log, 0 before the first.
func countRecords(t *testing.T, h *harness) int {
	t.Helper()
	if _, err := os.Stat(h.log); errors.Is(err, os.ErrNotExist) {
		return 0
	}
	return len(h.records(t))
}
