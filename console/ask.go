package console

import (
	"context"
	"errors"
	"fmt"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/ipc"
	"github.com/DavidGodefroid/lockkit/sanitize"
)

// Asker takes the human decisions of a console: it closes an approval
// screen with the prompt and turns the answer into an Approval. Server
// uses one; a product that draws its own approval screen (and prompts
// inside it, for values to type) uses one too, so that every approval is
// decided in one place.
type Asker struct {
	IO       IO
	Approver Approver
	// Profile is the profile name, typed to approve on production.
	Profile string
	// End ends the session (too many non-matching fingers); nil: ignored.
	End func(reason string)
	// Waiting, when set, is told when a decision starts (true) and ends
	// (false) waiting for the human.
	Waiting func(on bool)
}

// Ask is the prompt that closes an approval screen.
type Ask struct {
	// Frame is the colour of the screen's frame.
	Frame string
	// Production asks for the profile name typed instead of "y".
	Production bool
	// Retype, when set, is an answer that asks to retype values; Ask then
	// returns Approval.Retype. RetypeNote follows it in the prompt:
	// "(<Retype> to retype<RetypeNote>) ". An answer equal to the approval
	// answer is not offered.
	Retype, RetypeNote string
	// For names the decision in the fingerprint prompt (Decision.For); ""
	// is "to approve the request above".
	For string
}

// Decide asks the approver and explains a missing finger. Too many
// non-matching fingers end the console.
func (a Asker) Decide(ctx context.Context, d Decision) Result {
	r := a.approve(ctx, d)
	if r.Outcome == NoFinger {
		a.IO.Println(Paint.Fail("denied: " + sanitize.Terminal(r.Err.Error(), false)))
		if errors.Is(r.Err, ErrTooManyNoMatch) && a.End != nil {
			a.End("fingerprint: three non-matching fingers")
		}
	}
	return r
}

// approve asks the approver, telling Waiting around it.
func (a Asker) approve(ctx context.Context, d Decision) Result {
	if a.Waiting != nil {
		a.Waiting(true)
		defer a.Waiting(false)
	}
	return a.Approver.Approve(ctx, d)
}

// Ask rings the bell, prompts and decides. Every outcome but a retype is
// passed to record, filled with the event, the decision, the reason and the
// approval mode; the
// Refusal of a decision other than approved answers request id.
func (a Asker) Ask(ctx context.Context, id int64, q Ask, record func(audit.Base)) Approval {
	expected, prompt := "y", "Approve? [y/N] "
	if q.Production {
		expected = a.Profile
		prompt = fmt.Sprintf("Type the profile name %q to approve: ", a.Profile)
	}
	canRetype := q.Retype != "" && q.Retype != expected
	if canRetype {
		prompt = "(" + q.Retype + " to retype" + q.RetypeNote + ") " + prompt
	}
	if q.For == "" {
		q.For = "to approve the request above"
	}
	Bell(a.IO)
	d := Decision{Prompt: Paint.Paint(q.Frame, "╰─ ") + Paint.Bold(prompt), Expected: expected, Production: q.Production, For: q.For}
	if canRetype {
		d.Retype = q.Retype
	}
	r := a.Decide(ctx, d)
	var b audit.Base
	switch r.Outcome {
	case RetypeRequested:
		return Approval{Retype: true}
	case Approved:
		b.Event, b.Decision, b.Approval = audit.EventApproved, "approved", a.Approver.Mode()
		record(b)
		return Approval{Approved: true}
	case Unanswered:
		if ctx.Err() != nil {
			b.Event, b.Decision = audit.EventAbandoned, "abandoned"
			record(b)
			a.IO.Println(Paint.Fail("client gone: request cancelled"))
			return Approval{Refusal: ErrResp(id, ipc.CodeDenied, "the request was cancelled")}
		}
		b.Event, b.Decision = audit.EventTimeout, "timeout"
		record(b)
		a.IO.Println(Paint.Fail("no answer: denied"))
		return Approval{Refusal: ErrResp(id, ipc.CodeTimeout, "no answer from the human within the approval timeout; do not retry unless asked")}
	case NoFinger:
		b.Event, b.Decision, b.Reason, b.Error, b.Approval = audit.EventDenied, "denied", "no fingerprint", r.Err.Error(), a.Approver.Mode()
		record(b)
		return Approval{Refusal: ErrResp(id, ipc.CodeDenied, "denied by the human: no fingerprint; do not retry unless asked")}
	}
	b.Event, b.Decision = audit.EventDenied, "denied"
	msg := "denied by the human; do not retry unless asked"
	if reason := DenyReason(r.Answer); reason != "" {
		b.Reason = reason
		msg = "denied by the human: " + reason + "; do not retry unless asked"
		a.IO.Println(Paint.Fail("denied: " + reason))
	} else {
		a.IO.Println(Paint.Fail("denied"))
	}
	record(b)
	return Approval{Refusal: ErrResp(id, ipc.CodeDenied, msg)}
}
