package console

import (
	"context"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/ui"
)

// Asker is the decision step products with their own screen share with
// Server.Approve: the prompt, the outcomes, their records and answers.
func TestAskerOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, answer string
		production   bool
		timeout      bool
		cancel       bool
		want         Approval
		event        string
		reason       string
		line         string
	}{
		{name: "approved", answer: "y", want: Approval{Approved: true}, event: audit.EventApproved},
		{name: "production", answer: "prod", production: true, want: Approval{Approved: true}, event: audit.EventApproved},
		{name: "production y", answer: "y", production: true, event: audit.EventDenied, line: "denied"},
		{name: "retype", answer: "r", want: Approval{Retype: true}},
		{name: "denied", answer: "n", event: audit.EventDenied, line: "denied"},
		{name: "reason", answer: "no too wide", event: audit.EventDenied, reason: "too wide", line: "denied: too wide"},
		{name: "timeout", timeout: true, event: audit.EventTimeout, line: "no answer: denied"},
		{name: "abandoned", cancel: true, event: audit.EventAbandoned, line: "client gone: request cancelled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			io := &fakeIO{}
			if tc.answer != "" {
				io.answers = []string{tc.answer}
			}
			var waits []bool
			a := Asker{IO: io, Approver: NewTypedApprover(io), Profile: "prod", Waiting: func(on bool) { waits = append(waits, on) }}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			var recs []audit.Base
			got := a.Ask(ctx, 9, Ask{Frame: ui.Violet, Production: tc.production, Retype: "r", RetypeNote: " ${email}"}, func(b audit.Base) { recs = append(recs, b) })
			if got.Approved != tc.want.Approved || got.Retype != tc.want.Retype {
				t.Fatalf("approval %+v, want %+v", got, tc.want)
			}
			if len(waits) != 2 || !waits[0] || waits[1] {
				t.Errorf("waiting calls %v", waits)
			}
			wantPrompt := "(r to retype ${email}) Approve? [y/N] "
			if tc.production {
				wantPrompt = `(r to retype ${email}) Type the profile name "prod" to approve: `
			}
			if len(io.prompts) != 1 || !strings.Contains(io.prompts[0], wantPrompt) || !strings.Contains(io.prompts[0], "╰─ ") {
				t.Errorf("prompts %q, want %q", io.prompts, wantPrompt)
			}
			if tc.event == "" {
				if len(recs) != 0 {
					t.Errorf("a retype was recorded: %+v", recs)
				}
				return
			}
			if len(recs) != 1 || recs[0].Event != tc.event || recs[0].Reason != tc.reason {
				t.Fatalf("records %+v, want event %q reason %q", recs, tc.event, tc.reason)
			}
			if tc.event == audit.EventApproved {
				if recs[0].Approval != "session" || got.Refusal.Error != nil {
					t.Errorf("approved: record %+v refusal %+v", recs[0], got.Refusal)
				}
				return
			}
			if got.Refusal.Error == nil || got.Refusal.ID != 9 {
				t.Fatalf("refusal %+v", got.Refusal)
			}
			code := ipc.CodeDenied
			if tc.timeout {
				code = ipc.CodeTimeout
			}
			if got.Refusal.Error.Code != code {
				t.Errorf("code %d, want %d", got.Refusal.Error.Code, code)
			}
			if !strings.Contains(strings.Join(io.out, "\n"), tc.line) {
				t.Errorf("console %q lacks %q", io.out, tc.line)
			}
		})
	}
}

// The approval answer itself is never offered as the retype answer.
func TestAskerNoRetypeOnTheApprovalAnswer(t *testing.T) {
	io := &fakeIO{answers: []string{"r"}}
	a := Asker{IO: io, Approver: NewTypedApprover(io), Profile: "r"}
	got := a.Ask(context.Background(), 1, Ask{Production: true, Retype: "r"}, func(audit.Base) {})
	if !got.Approved || strings.Contains(io.prompts[0], "to retype") {
		t.Fatalf("approval %+v, prompt %q", got, io.prompts[0])
	}
}
