//go:build unix

package console

import (
	"context"
	"strings"
	"testing"
)

// On production, the console's own widenings take the typed profile name,
// exactly, like a request (#8): allowing unmasked output and applying a
// loosening at :review. "y" and another case refuse them.
func TestServerProductionWideningTypedName(t *testing.T) {
	h := newHarness(t, prod(), nil)
	const unmask = `Allow unmasked output? Type the profile name "prod" to allow it: `
	for _, ans := range []string{"y", "PROD"} {
		h.io.answers = []string{ans}
		h.s.Command(context.Background(), ":unmask")
		if h.s.UnmaskAllowed() {
			t.Fatalf("unmask allowed on production by %q", ans)
		}
		if p := h.io.promptList(); p[len(p)-1] != unmask {
			t.Fatalf("unmask prompt %q", p[len(p)-1])
		}
	}
	h.io.answers = []string{"prod"}
	h.s.Command(context.Background(), ":unmask")
	if !h.s.UnmaskAllowed() {
		t.Fatalf("unmask not allowed on the typed name:\n%s", h.io.plain())
	}
	if rec := h.lastRecord(t); rec["event"] != "unmask" || rec["decision"] != "allowed" {
		t.Fatalf("unmask audit: %v", rec)
	}
	// Turning it off narrows: no prompt.
	n := h.io.promptCount()
	h.s.Command(context.Background(), ":unmask")
	if h.s.UnmaskAllowed() || h.io.promptCount() != n {
		t.Fatal("unmask off asked or failed")
	}

	const review = `Apply these changes? Type the profile name "prod" to apply them: `
	looser := prod()
	looser.Tier = "peek"
	for _, ans := range []string{"y", "PROD"} {
		h.b.policy = looser
		h.s.CheckPolicy()
		h.io.answers = []string{ans}
		h.s.Command(context.Background(), ":review")
		if p := h.io.promptList(); p[len(p)-1] != review {
			t.Fatalf("review prompt %q", p[len(p)-1])
		}
		if !strings.Contains(h.io.plain(), "policy change refused") {
			t.Fatalf("loosening applied on production by %q:\n%s", ans, h.io.plain())
		}
		// A refused policy is not offered again: change it to retry.
		looser.MaxRows++
	}
	h.b.policy = looser
	h.s.CheckPolicy()
	h.io.answers = []string{"prod"}
	h.s.Command(context.Background(), ":review")
	if !strings.Contains(h.io.plain(), "policy change applied") {
		t.Fatalf("loosening not applied on the typed name:\n%s", h.io.plain())
	}
	if rec := h.lastRecord(t); rec["event"] != "policy" || rec["decision"] != "applied" {
		t.Fatalf("policy audit: %v", rec)
	}

	// Turning production off is a loosening of a production profile: the
	// name too.
	off := looser
	off.Production = false
	h.b.policy = off
	h.s.CheckPolicy()
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	if p := h.io.promptList(); p[len(p)-1] != review {
		t.Fatalf("production off prompt %q", p[len(p)-1])
	}
}

// Outside production the widenings keep their "y" (any case).
func TestServerWideningYOutsideProduction(t *testing.T) {
	h := newHarness(t, uat(), nil)
	h.io.answers = []string{"Y"}
	h.s.Command(context.Background(), ":unmask")
	if p := h.io.promptList(); !h.s.UnmaskAllowed() || p[len(p)-1] != "Allow unmasked output? [y/N] " {
		t.Fatalf("unmask %v prompt %q", h.s.UnmaskAllowed(), p[len(p)-1])
	}
	looser := uat()
	looser.Tier = "peek"
	h.b.policy = looser
	h.s.CheckPolicy()
	h.io.answers = []string{"y"}
	h.s.Command(context.Background(), ":review")
	if p := h.io.promptList(); p[len(p)-1] != "Apply these changes? [y/N] " || !strings.Contains(h.io.plain(), "policy change applied") {
		t.Fatalf("review prompt %q:\n%s", p[len(p)-1], h.io.plain())
	}
}

func TestWidenDecision(t *testing.T) {
	d := WidenDecision("Allow it?", "allow it", "to allow it", false, "prod")
	if d.Prompt != "Allow it? [y/N] " || d.Expected != "y" || d.Production || d.For != "to allow it" {
		t.Fatalf("outside production: %+v", d)
	}
	d = WidenDecision("Allow it?", "allow it", "to allow it", true, "prod")
	if d.Prompt != `Allow it? Type the profile name "prod" to allow it: ` || d.Expected != "prod" || !d.Production || d.For != "to allow it" {
		t.Fatalf("production: %+v", d)
	}
	// The typed approver matches it exactly.
	for ans, want := range map[string]Outcome{"prod": Approved, "PROD": Denied, "y": Denied, " prod ": Approved} {
		io := &fakeIO{answers: []string{ans}}
		if r := NewTypedApprover(io).Approve(context.Background(), d); r.Outcome != want {
			t.Errorf("%q: outcome %v, want %v", ans, r.Outcome, want)
		}
	}
}
