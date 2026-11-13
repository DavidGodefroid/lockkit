//go:build unix

package console

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/managed"
)

// ManagedBounds reads [lockmq.bounds] tier and limits.max_rows: the
// ceiling is p with each bounded field set to its bound.
func (b *fakeBackend) ManagedBounds(p Policy, m *managed.File) (managed.Bounds, error) {
	var bounds struct {
		Tier   string `toml:"tier"`
		Limits struct {
			MaxRows int `toml:"max_rows"`
		} `toml:"limits"`
	}
	ok, err := m.Decode(&bounds, "lockmq", managed.KindBounds)
	if err != nil || !ok {
		return managed.Bounds{}, err
	}
	c := p.(fakePolicy)
	if bounds.Tier != "" {
		c.Tier = bounds.Tier
	}
	if bounds.Limits.MaxRows != 0 {
		c.MaxRows = bounds.Limits.MaxRows
	}
	return managed.Bounds{Ceiling: c}, nil
}

// plainBackend is a backend that does not apply managed bounds.
type plainBackend struct{ Backend }

// managedFile is a managed file the test changes while a console runs.
type managedFile struct {
	mu  sync.Mutex
	f   *managed.File
	err error
}

func newManaged(t *testing.T, data string) *managedFile {
	t.Helper()
	m := &managedFile{}
	m.set(t, data)
	return m
}

func (m *managedFile) set(t *testing.T, data string) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if data == "" {
		m.f = nil
		return
	}
	f, err := managed.Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	m.f = f
}

func (m *managedFile) fail(err error) { m.mu.Lock(); m.err = err; m.mu.Unlock() }

func (m *managedFile) load(context.Context) (*managed.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.f, m.err
}

func (m *managedFile) fp() string { m.mu.Lock(); defer m.mu.Unlock(); return m.f.Fingerprint }

const peekBound = "version = 1\norganisation = \"Example Corp\"\n[lockmq.bounds]\ntier = \"peek\"\nlimits.max_rows = 50\n"
const readBound = "version = 1\norganisation = \"Example Corp\"\n[lockmq.bounds]\ntier = \"read\"\nlimits.max_rows = 50\n"

// A policy beyond the bounds is refused at start, citing the managed key,
// with no prompt; audited refused-managed.
func TestRunRefusesBeyondManagedBounds(t *testing.T) {
	m := newManaged(t, readBound)
	b := &fakeBackend{policy: uat()}
	b.policy.Tier = "peek"
	io := &fakeIO{answers: []string{"y"}, secrets: []string{"pw"}}
	state := t.TempDir()
	err := Run(context.Background(), testProduct, b, Options{Profile: "uat", Hub: testHub(t), IO: io, StateDir: state, Isolation: runEnv(t),
		Harden: func() error { return nil }, loadManaged: m.load})
	if !errors.Is(err, ErrManaged) || !strings.Contains(err.Error(), "blocked by company policy: lockmq.bounds.tier = read (profile uat: tier = peek)") {
		t.Fatalf("Run: %v", err)
	}
	if io.promptCount() != 0 || len(b.creds) != 0 {
		t.Fatalf("prompts %v, connections %d", io.promptList(), len(b.creds))
	}
	if !strings.Contains(io.plain(), "Managed by Example Corp (sha256:") {
		t.Fatalf("managed line missing:\n%s", io.plain())
	}
	rec := lastRecordOf(t, state)
	if rec["decision"] != DecisionRefusedManaged || rec["managed"] != m.fp() || !strings.Contains(rec["error"].(string), "lockmq.bounds.tier") {
		t.Fatalf("audit %v", rec)
	}
	if ok, _ := config.LoadApproved(testProduct, state, "user-uat", &fakePolicy{}); ok {
		t.Fatal("a refused policy was saved")
	}
}

// The last approved policy, kept after a refused loosening, is checked too.
func TestRunRefusesApprovedPolicyBeyondManagedBounds(t *testing.T) {
	state := t.TempDir()
	old := uat()
	old.Tier = "peek"
	if err := config.SaveApproved(testProduct, state, "user-uat", old); err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{policy: uat()}
	b.policy.MaxRows = 0 // a loosening the human refuses: the approved policy stays
	m := newManaged(t, "version = 1\n[lockmq.bounds]\ntier = \"read\"\n")
	io := &fakeIO{answers: []string{"n"}, secrets: []string{"pw"}}
	err := Run(context.Background(), testProduct, b, Options{Profile: "uat", Hub: testHub(t), IO: io, StateDir: state, Isolation: runEnv(t),
		Harden: func() error { return nil }, loadManaged: m.load})
	if !errors.Is(err, ErrManaged) || !strings.Contains(err.Error(), "tier = peek") {
		t.Fatalf("Run: %v\n%s", err, io.plain())
	}
}

// Unreadable, badly owned or badly signed: the start is refused.
func TestRunRefusesUnreadableManaged(t *testing.T) {
	m := &managedFile{err: errors.New("managed: /etc/lockfamily/managed.toml must be owned by root (it is owned by uid 1000)")}
	io := &fakeIO{answers: []string{"y"}, secrets: []string{"pw"}}
	state := t.TempDir()
	err := Run(context.Background(), testProduct, &fakeBackend{policy: uat()}, Options{Profile: "uat", Hub: testHub(t), IO: io, StateDir: state,
		Isolation: runEnv(t), Harden: func() error { return nil }, loadManaged: m.load})
	if !errors.Is(err, ErrManaged) || !strings.Contains(err.Error(), "must be owned by root") || io.promptCount() != 0 {
		t.Fatalf("Run: %v, prompts %v", err, io.promptList())
	}
	if rec := lastRecordOf(t, state); rec["decision"] != DecisionRefusedManaged {
		t.Fatalf("audit %v", rec)
	}
}

// A product that does not apply managed bounds refuses a file that has a
// section for it, and runs under a file that has none.
func TestRunRefusesManagedSectionNotApplied(t *testing.T) {
	m := newManaged(t, readBound)
	io := &fakeIO{answers: []string{"y"}, secrets: []string{"pw"}}
	err := Run(context.Background(), testProduct, plainBackend{&fakeBackend{policy: uat()}}, Options{Profile: "uat", Hub: testHub(t), IO: io,
		StateDir: t.TempDir(), Isolation: runEnv(t), Harden: func() error { return nil }, loadManaged: m.load})
	if !errors.Is(err, ErrManaged) || !strings.Contains(err.Error(), "does not apply it: update lockmq") {
		t.Fatalf("Run: %v", err)
	}
	vs, err := managedViolations(testProduct, plainBackend{&fakeBackend{}}, uat(), newManaged(t, "version = 1\n[locksql.bounds]\ntier = \"read\"\n").f)
	if err != nil || vs != nil {
		t.Fatalf("other tool's section: %v, %v", vs, err)
	}
}

// A policy within the bounds is approved as usual; the managed
// fingerprint is recorded in the approved file and in every audit record.
func TestRunRecordsManagedFingerprint(t *testing.T) {
	m := newManaged(t, peekBound)
	b := &fakeBackend{policy: uat()}
	io := &fakeIO{answers: []string{"y"}, secrets: []string{"pw"}}
	state := t.TempDir()
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), testProduct, b, Options{Profile: "uat", Hub: testHub(t), IO: io, StateDir: state, Isolation: runEnv(t),
			Harden: func() error { return nil }, Ready: func(s string) { ready <- s }, loadManaged: m.load})
	}()
	var socket string
	select {
	case socket = <-ready:
	case err := <-done:
		t.Fatalf("Run: %v\n%s", err, io.plain())
	case <-time.After(10 * time.Second):
		t.Fatal("no socket")
	}
	dialAndCall(t, socket, ipc.MethodLogout, nil)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	path, _ := config.ApprovedPath(testProduct, state, "user-uat")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil || obj[config.ManagedField] != m.fp() {
		t.Fatalf("approved file %s: %v", raw, err)
	}
	var ap fakePolicy
	if ok, err := config.LoadApproved(testProduct, state, "user-uat", &ap); !ok || err != nil || ap.Tier != "read" {
		t.Fatalf("approved policy does not load back: %+v, %v", ap, err)
	}
	recs := recordsOf(t, state)
	if len(recs) < 3 {
		t.Fatalf("records %v", recs)
	}
	for _, r := range recs {
		if r["managed"] != m.fp() {
			t.Fatalf("record without the managed fingerprint: %v", r)
		}
	}
}

// While running: a loosening beyond the bounds is refused without a
// prompt, audited once, shown by :review as not approvable; a tightening
// is accepted; a loosening within the bounds still waits for the human.
func TestCheckPolicyRefusesBeyondManagedBounds(t *testing.T) {
	m := newManaged(t, peekBound)
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Managed, c.LoadManaged = m.f, m.load })

	beyond := uat()
	beyond.MaxRows = 0 // unlimited, beyond limits.max_rows = 50
	h.b.policy = beyond
	h.s.CheckPolicy()
	h.s.CheckPolicy()
	if h.s.PolicyPending() || !h.s.PolicyRefused() || h.s.Policy().(fakePolicy).MaxRows != 20 {
		t.Fatal("a loosening beyond the bounds is pending or applied")
	}
	n := 0
	for _, r := range h.records(t) {
		if r["decision"] == DecisionRefusedManaged {
			n++
			if r["managed"] != m.fp() || !strings.Contains(r["error"].(string), "lockmq.bounds.limits.max_rows = 50 (profile uat: limits.max_rows = 0)") {
				t.Fatalf("record %v", r)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d refused-managed records", n)
	}
	h.s.Command(context.Background(), ":review")
	if h.io.promptCount() != 0 || !strings.Contains(h.io.plain(), "refused by the company's managed configuration (not approvable)") {
		t.Fatalf("review: prompts %v\n%s", h.io.promptList(), h.io.plain())
	}

	tighter := uat()
	tighter.MaxRows = 10
	h.b.policy = tighter
	h.s.CheckPolicy()
	if h.s.Policy().(fakePolicy).MaxRows != 10 || h.s.PolicyRefused() {
		t.Fatal("a tightening within the bounds not applied")
	}
	path, _ := config.ApprovedPath(testProduct, h.state, "user-uat")
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), m.fp()) {
		t.Fatalf("approved file without the managed fingerprint: %s", raw)
	}

	within := tighter
	within.Tier = "peek"
	h.b.policy = within
	h.s.CheckPolicy()
	if !h.s.PolicyPending() {
		t.Fatal("a loosening within the bounds is not pending")
	}
	// The company tightens the bound: the pending loosening is dropped.
	m.set(t, readBound)
	h.s.CheckPolicy()
	if h.s.PolicyPending() || !h.s.PolicyRefused() {
		t.Fatal("a pending loosening beyond the new bounds survives")
	}
}

// The managed file changes while running: recorded; a stricter file
// replaces the policy in force at once with the files' policy when that
// one is within it, and ends the session otherwise.
func TestManagedChangeWhileRunning(t *testing.T) {
	m := newManaged(t, peekBound)
	start := uat()
	start.Tier = "peek"
	h := newHarness(t, start, func(c *ServerConfig) { c.Managed, c.LoadManaged = m.f, m.load })

	// The user already tightened the files to tier read: adopted at once.
	h.b.policy = uat()
	m.set(t, readBound)
	h.s.CheckPolicy()
	if _, ended := h.s.Ended(); ended || h.s.Policy().(fakePolicy).Tier != "read" {
		t.Fatalf("not tightened to the new bounds:\n%s", h.io.plain())
	}
	recs := h.records(t)
	if recs[0]["decision"] != DecisionManagedChanged || recs[0]["managed"] != m.fp() {
		t.Fatalf("change not recorded: %v", recs)
	}

	// Removed by the admin: recorded, the policy in force kept.
	m.set(t, "")
	h.s.CheckPolicy()
	if r := h.lastRecord(t); r["decision"] != DecisionManagedChanged || r["managed"] != nil {
		t.Fatalf("removal: %v", r)
	}

	// The files go beyond a stricter file: the session ends.
	h2 := newHarness(t, start, func(c *ServerConfig) { c.Managed, c.LoadManaged = m.f, m.load })
	m.set(t, readBound)
	h2.s.CheckPolicy()
	if reason, ended := h2.s.Ended(); !ended || !strings.Contains(reason, "beyond the managed configuration") {
		t.Fatalf("session not ended: %q\n%s", reason, h2.io.plain())
	}
}

// A managed file that becomes unreadable while running ends the session.
func TestManagedUnreadableWhileRunningEnds(t *testing.T) {
	m := newManaged(t, peekBound)
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Managed, c.LoadManaged = m.f, m.load })
	h.s.CheckPolicy()
	if _, ended := h.s.Ended(); ended {
		t.Fatal("ended with a readable file")
	}
	m.fail(errors.New("managed: signature does not verify"))
	h.s.CheckPolicy()
	if reason, ended := h.s.Ended(); !ended || !strings.Contains(reason, "cannot be read") {
		t.Fatalf("session not ended: %q", reason)
	}
	if r := h.lastRecord(t); r["decision"] != DecisionRefusedManaged {
		t.Fatalf("audit %v", r)
	}
}

func recordsOf(t *testing.T, state string) []map[string]any {
	t.Helper()
	h := &harness{log: filepath.Join(state, testProduct.Name, "audit.log")}
	return h.records(t)
}

func lastRecordOf(t *testing.T, state string) map[string]any {
	t.Helper()
	recs := recordsOf(t, state)
	if len(recs) == 0 {
		t.Fatal("no audit record")
	}
	return recs[len(recs)-1]
}

// A product with its own start-up builds its server with NewServer and sets
// LoadManaged: a stricter file at the next poll is recorded and ends the
// session when the policy in force is beyond it, as under Run.
func TestNewServerLoadManagedReloads(t *testing.T) {
	a := newManaged(t, peekBound)
	b := newManaged(t, readBound)
	start := uat()
	start.Tier = "peek"
	h := newHarness(t, start, func(c *ServerConfig) { c.Managed, c.LoadManaged = a.f, b.load })
	h.s.CheckPolicy()
	recs := h.records(t)
	if len(recs) == 0 || recs[0]["decision"] != DecisionManagedChanged || recs[0]["managed"] != b.fp() {
		t.Fatalf("change not recorded: %v", recs)
	}
	if reason, ended := h.s.Ended(); !ended || !strings.Contains(reason, "beyond the managed configuration") {
		t.Fatalf("session not ended: %q\n%s", reason, h.io.plain())
	}
}

// LoadManaged nil keeps Managed for the session: no re-read, no record.
func TestNewServerWithoutLoadManagedKeepsManaged(t *testing.T) {
	a := newManaged(t, readBound)
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Managed = a.f })
	h.s.CheckPolicy()
	h.s.CheckPolicy()
	if _, ended := h.s.Ended(); ended {
		t.Fatal("session ended")
	}
	if recs := h.records(t); len(recs) != 0 {
		t.Fatalf("records %v", recs)
	}
	if h.s.managed != a.f {
		t.Fatal("managed file replaced")
	}
}

func TestCheckManaged(t *testing.T) {
	b := &fakeBackend{policy: uat()}
	if err := CheckManaged(testProduct, b, uat(), nil); err != nil {
		t.Fatalf("nil file: %v", err)
	}
	read := newManaged(t, readBound).f
	if err := CheckManaged(testProduct, b, uat(), read); err != nil {
		t.Fatalf("within the bounds: %v", err)
	}
	if ManagedLines(errors.New("other")) != nil {
		t.Fatal("lines of another error")
	}

	beyond := uat()
	beyond.Tier, beyond.MaxRows = "peek", 0
	bounds, err := b.ManagedBounds(beyond, read)
	if err != nil {
		t.Fatal(err)
	}
	bounds.Tool, bounds.Profile = testProduct.Name, beyond.Name
	var want []string
	for _, v := range managed.Check(beyond, bounds) {
		want = append(want, v.String())
	}
	if len(want) != 2 {
		t.Fatalf("violations %v", want)
	}
	err = CheckManaged(testProduct, b, beyond, read)
	if !errors.Is(err, ErrManaged) || !strings.Contains(err.Error(), want[0]) {
		t.Fatalf("beyond the bounds: %v", err)
	}
	if got := ManagedLines(err); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines %q, want %q", got, want)
	}

	// A backend that does not apply the bounds, with a section for it.
	err = CheckManaged(testProduct, plainBackend{b}, uat(), read)
	if lines := ManagedLines(err); !errors.Is(err, ErrManaged) || len(lines) != 1 || !strings.Contains(lines[0], "does not apply it") {
		t.Fatalf("plain backend: %v, %q", err, lines)
	}
	if err := CheckManaged(testProduct, plainBackend{b}, uat(), newManaged(t, "version = 1\n[locksql.bounds]\ntier = \"read\"\n").f); err != nil {
		t.Fatalf("plain backend, no section: %v", err)
	}
}
