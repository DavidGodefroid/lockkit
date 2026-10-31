//go:build unix

package console

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ipc"
)

// startPolicyOnly runs a policy-only console on state and returns its
// socket, its stop and its result.
func startPolicyOnly(t *testing.T, b *fakeBackend, io *fakeIO, state string) (string, context.CancelFunc, chan error) {
	t.Helper()
	env := runEnv(t)
	ready := make(chan string, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		done <- Run(ctx, testProduct, b, Options{Profile: "uat", PolicyOnly: true, IO: io, StateDir: state, Isolation: env,
			Harden: func() error { return nil }, Quantum: -1, Ready: func(s string) { ready <- s }})
	}()
	select {
	case s := <-ready:
		return s, cancel, done
	case err := <-done:
		cancel()
		t.Fatalf("Run: %v\n%s", err, io.plain())
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("no socket")
	}
	return "", cancel, done
}

// askedApply reports whether io was asked to apply policy changes.
func askedApply(io *fakeIO) bool {
	io.mu.Lock()
	defer io.mu.Unlock()
	for _, p := range io.prompts {
		if strings.Contains(p, "Apply these changes?") {
			return true
		}
	}
	return false
}

func stopRun(t *testing.T, cancel context.CancelFunc, done chan error) {
	t.Helper()
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func auditRecords(t *testing.T, state string) []map[string]any {
	t.Helper()
	f, err := os.Open(filepath.Join(state, testProduct.Name, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// A policy-only console starts without any hub option: its policy is
// reviewed on its terminal, it listens, and a request a handler hands to
// Env.Approve is refused, never asked here nor approved, though the
// terminal would answer y. No hub client is opened: no hub state, no
// instance key in the home.
func TestRunPolicyOnlyStartsWithoutHubAndApprovesNoRequest(t *testing.T) {
	// The home, where OpenHub would make the instance key: left empty.
	home := t.TempDir()
	t.Setenv("HOME", home)
	b := &fakeBackend{policy: uat()}
	io := &fakeIO{answers: []string{"y", "y", "y", "y"}, secrets: []string{"s3cret"}}
	state := t.TempDir()
	socket, cancel, done := startPolicyOnly(t, b, io, state)
	// The policy review and the secret (credentials ask).
	if io.promptCount() != 2 || !askedApply(io) || !strings.Contains(io.plain(), "First start of profile uat") {
		t.Fatalf("start: prompts %v\n%s", io.prompts, io.plain())
	}
	if !strings.Contains(io.plain(), "Policy only: this console serves its policy and approves no request") || strings.Contains(io.plain(), "lockhub at") {
		t.Fatalf("start line:\n%s", io.plain())
	}
	for i := 0; i < 2; i++ {
		r := dialAndCall(t, socket, "op.read", map[string]string{"queue": "orders"})
		if r.Error == nil || r.Error.Code != ipc.CodeDenied || !strings.Contains(r.Error.Message, "policy only") {
			t.Fatalf("request %d: %+v %s", i, r.Error, r.Result)
		}
	}
	stopRun(t, cancel, done)
	if io.promptCount() != 2 || io.bells != 0 {
		t.Fatalf("a request was asked on the terminal: prompts %d bells %d\n%s", io.promptCount(), io.bells, io.plain())
	}
	var refused int
	for _, rec := range auditRecords(t, state) {
		switch rec["event"] {
		case "approved", "pending", "auto":
			t.Fatalf("request not refused: %v", rec)
		case "refused":
			if rec["decision"] != "refused" || rec["reason"] != "policy-only console" {
				t.Fatalf("refusal audit: %v", rec)
			}
			refused++
		}
	}
	if refused != 2 {
		t.Fatalf("%d refusals audited, want 2", refused)
	}
	if _, err := os.Stat(filepath.Join(state, testProduct.Name, "hub")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hub state written: %v", err)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("home written (no hub client, no instance key): %v", entries)
	}
}

// A loosening of the policy of a policy-only console is asked on its
// terminal: refused, the console keeps the approved policy; approved, it
// serves the looser one.
func TestRunPolicyOnlyLooseningAskedOnTerminal(t *testing.T) {
	state := t.TempDir()
	io := &fakeIO{answers: []string{"y"}, secrets: []string{"s3cret"}}
	_, cancel, done := startPolicyOnly(t, &fakeBackend{policy: uat()}, io, state)
	stopRun(t, cancel, done)

	looser := uat()
	looser.Tier = "peek"
	for _, tc := range []struct{ answer, tier string }{{"n", "read"}, {"y", "peek"}} {
		b := &fakeBackend{policy: looser}
		io := &fakeIO{answers: []string{tc.answer}, secrets: []string{"s3cret"}}
		_, cancel, done := startPolicyOnly(t, b, io, state)
		if !askedApply(io) || !strings.Contains(io.plain(), "tier: read → peek") {
			t.Fatalf("%s: loosening not asked: prompts %v\n%s", tc.answer, io.prompts, io.plain())
		}
		stopRun(t, cancel, done)
		ap, ok, err := loadApproved(testProduct, state, "user-uat", looser)
		if err != nil || !ok || ap.(fakePolicy).Tier != tc.tier {
			t.Fatalf("%s: approved %+v %v %v, want tier %s", tc.answer, ap, ok, err, tc.tier)
		}
	}
}

// Policy-only with any hub option is ambiguous (who decides the
// requests?), and OnHub has no hub to get: both refused before any
// prompt, session or file.
func TestRunPolicyOnlyRefusesHubOptions(t *testing.T) {
	for name, tc := range map[string]struct {
		o    Options
		want error
	}{
		"hub":        {Options{Hub: HubOptions{URL: "http://lockhub:8443", KeyFile: "/k", Instance: "web"}}, ErrPolicyOnlyHub},
		"plain-http": {Options{Hub: HubOptions{PlainHTTP: true}}, ErrPolicyOnlyHub},
		"devices":    {Options{Hub: HubOptions{DevicesFile: "/d"}}, ErrPolicyOnlyHub},
		"on-hub":     {Options{OnHub: func(*Hub) {}}, ErrConfig},
	} {
		b := &fakeBackend{policy: uat()}
		io := &fakeIO{answers: []string{"y"}}
		o := tc.o
		state := t.TempDir()
		o.PolicyOnly, o.Profile, o.IO, o.StateDir, o.Isolation, o.Harden = true, "uat", io, state, runEnv(t), func() error { return nil }
		err := Run(context.Background(), testProduct, b, o)
		if !errors.Is(err, tc.want) || !errors.Is(err, ErrConfig) {
			t.Fatalf("%s: %v, want %v", name, err, tc.want)
		}
		if io.promptCount() != 0 || len(b.sessions) != 0 || io.plain() != "" {
			t.Fatalf("%s: prompts %d sessions %d output %q", name, io.promptCount(), len(b.sessions), io.plain())
		}
		if entries, _ := os.ReadDir(state); len(entries) != 0 {
			t.Fatalf("%s: state written: %v", name, entries)
		}
	}
	// Without PolicyOnly, no hub is still ErrNoHub.
	io := &fakeIO{}
	err := Run(context.Background(), testProduct, &fakeBackend{policy: uat()}, Options{Profile: "uat", IO: io, StateDir: t.TempDir(), Isolation: runEnv(t)})
	if !errors.Is(err, ErrNoHub) {
		t.Fatalf("no hub: %v", err)
	}
}

// The policy-only approver: a request is refused even through Approve
// (never asked), the console's own decisions (:unmask, a loosening at
// :review) go to the terminal approver it wraps.
func TestPolicyOnlyApprover(t *testing.T) {
	h := newHarness(t, uat(), func(c *ServerConfig) { c.Approver = PolicyOnlyApprover(NewTypedApprover(c.IO)) })
	h.io.answers = []string{"y", "y", "y"}
	if r := h.s.approver.Approve(context.Background(), Decision{Prompt: "Approve? ", Expected: "y", Screen: &Screen{}}); r.Outcome != Denied || !errors.Is(r.Err, ErrPolicyOnly) {
		t.Fatalf("request through Approve: %+v", r)
	}
	if r := h.call(t, context.Background(), "op.read", map[string]string{"queue": "orders"}); r.Error == nil || r.Error.Code != ipc.CodeDenied {
		t.Fatalf("request: %+v %s", r.Error, r.Result)
	}
	if h.io.promptCount() != 0 {
		t.Fatalf("a request was asked: %d prompts\n%s", h.io.promptCount(), h.io.plain())
	}
	h.s.Command(context.Background(), ":unmask")
	if !h.s.UnmaskAllowed() || h.io.promptCount() != 1 {
		t.Fatalf("unmask %v prompts %d\n%s", h.s.UnmaskAllowed(), h.io.promptCount(), h.io.plain())
	}
	looser := uat()
	looser.Tier = "peek"
	h.b.policy = looser
	h.s.CheckPolicy()
	h.s.Command(context.Background(), ":review")
	if h.s.approved.(fakePolicy).Tier != "peek" || h.io.promptCount() != 2 {
		t.Fatalf("policy change: tier %q prompts %d\n%s", h.s.approved.(fakePolicy).Tier, h.io.promptCount(), h.io.plain())
	}
	if rec := h.lastRecord(t); rec["event"] != "policy" || rec["decision"] != "applied" || rec["approval"] != "session" {
		t.Fatalf("policy audit: %v", rec)
	}
}
