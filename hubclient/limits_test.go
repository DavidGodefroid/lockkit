package hubclient_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// hashN is the plan hash of the i-th plan of a test.
func hashN(i int) string { return fmt.Sprintf("sha256:%064x", i+1) }

// auto makes a decision one of `lox run`'s auto rules took.
func auto(d *ticket.Decision) {
	d.V, d.Rule = ticket.VersionKinds, &ticket.Rule{By: ticket.RuleAuto, ID: "default:read"}
}

// submitN submits plan i of e.
func submitN(t *testing.T, e *env, i int) (string, error) {
	t.Helper()
	p, tk := e.plan(t, hashN(i))
	return e.client.Submit(context.Background(), e.store, p.ID, caller, tk, screen())
}

func rateErr(t *testing.T, err error) *hubclient.RateLimitError {
	t.Helper()
	var re *hubclient.RateLimitError
	if !errors.As(err, &re) || !errors.Is(err, hubclient.ErrRateLimited) {
		t.Fatalf("error %v, want a RateLimitError", err)
	}
	return re
}

func TestDefaultLimits(t *testing.T) {
	l := hubclient.DefaultLimits()
	if l.RateN != 30 || l.RateWindow != 5*time.Minute || l.MaxPending != 30 || l.RateTotal != 300 {
		t.Fatalf("defaults %+v", l)
	}
	if got := (hubclient.Limits{RateN: 600}).Effective(); got.RateTotal != 600 || got.MaxPending != 30 || got.RateWindow != 5*time.Minute {
		t.Fatalf("effective %+v: the safety cap is never below RateN", got)
	}
}

// The 31st ticket a human must decide in 5 minutes is refused with the
// limit, the count, the setting and when the next one is accepted.
func TestRateDefaultThirtyThenRetryAfter(t *testing.T) {
	e, c := newClockEnv(t, nil)
	for i := range 30 {
		if _, err := submitN(t, e, i); err != nil {
			t.Fatalf("ticket %d: %v", i+1, err)
		}
		if i == 0 {
			c.add(18 * time.Second)
		}
	}
	_, err := submitN(t, e, 30)
	re := rateErr(t, err)
	if re.Limit != hubclient.LimitRate || re.Count != 30 || re.Max != 30 || re.Window != 5*time.Minute {
		t.Fatalf("refusal %+v", re)
	}
	if re.RetryAfter != 5*time.Minute-18*time.Second {
		t.Fatalf("retry after %s", re.RetryAfter)
	}
	for _, want := range []string{"30 tickets for a human in 5m0s", "limit 30", "limits.tickets_per_window", "retry after 4m42s"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not say %q", err, want)
		}
	}
	if e.hub.Pushed() != 30 {
		t.Errorf("hub got %d tickets", e.hub.Pushed())
	}
	// Once the first ticket leaves the window, one more is accepted (the
	// 30 pending ones are then the bound).
	c.add(re.RetryAfter)
	if _, err := submitN(t, e, 30); err == nil {
		t.Fatal("31 pending tickets, over MaxPending")
	} else if re := rateErr(t, err); re.Limit != hubclient.LimitPending || re.RetryAfter != 0 {
		t.Fatalf("refusal %+v", re)
	}
}

func TestPendingCapMessage(t *testing.T) {
	e := newEnv(t, func(c *hubclient.Config) { c.MaxPending = 1 })
	if _, err := submitN(t, e, 0); err != nil {
		t.Fatal(err)
	}
	_, err := submitN(t, e, 1)
	if re := rateErr(t, err); re.Limit != hubclient.LimitPending || re.Count != 1 || !strings.Contains(err.Error(), "limits.max_pending") {
		t.Fatalf("refusal %v", err)
	}
}

// decideRun has the hub decide ticket id (mod), polls it in, and runs the
// plan to its end, as a lock does with an approval.
func decideRun(t *testing.T, e *env, id string, mod func(*ticket.Decision)) {
	t.Helper()
	ctx := context.Background()
	e.hub.DecideWith(id, ticket.Approved, "", nil, mod)
	if _, err := e.client.Poll(ctx, 0); err != nil {
		t.Fatal(err)
	}
	p, _, err := e.client.Begin(e.store, id, caller, func(p *plans.Plan) (string, string, error) {
		return policyFP, p.Binding.PlanHash, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.client.Finish(ctx, e.store, p.ID, caller, true, ""); err != nil {
		t.Fatal(err)
	}
}

// An agent analysing a database: 40 reads `lox run` approves on its own
// in 5 minutes all go through; 31 questions for the human throttle at 30.
func TestReadsThenQuestionsE2E(t *testing.T) {
	e, c := newClockEnv(t, nil)
	for i := range 40 {
		id, err := submitN(t, e, i)
		if err != nil {
			t.Fatalf("auto-approved read %d: %v", i+1, err)
		}
		decideRun(t, e, id, auto)
		c.add(7 * time.Second)
	}
	for i := range 30 {
		if _, err := submitN(t, e, 40+i); err != nil {
			t.Fatalf("question %d: %v", i+1, err)
		}
	}
	_, err := submitN(t, e, 70)
	if re := rateErr(t, err); re.Limit != hubclient.LimitRate || re.Count != 30 || re.RetryAfter <= 0 {
		t.Fatalf("31st question: %+v", re)
	}
}

// Tickets an auto rule decided do not use the budget of the human's
// questions; the safety cap still counts them.
func TestAutoDecidedLeaveTheRate(t *testing.T) {
	e := newEnv(t, func(c *hubclient.Config) { c.RateN, c.RateTotal, c.MaxPending = 2, 5, 100 })
	ctx := context.Background()
	for i := range 5 {
		id, err := submitN(t, e, i)
		if err != nil {
			t.Fatalf("auto ticket %d: %v", i+1, err)
		}
		e.hub.DecideWith(id, ticket.Approved, "", nil, auto)
		if _, err := e.client.Poll(ctx, 0); err != nil {
			t.Fatal(err)
		}
	}
	_, err := submitN(t, e, 5)
	if re := rateErr(t, err); re.Limit != hubclient.LimitTotal || re.Count != 5 || re.Max != 5 || re.RetryAfter <= 0 ||
		!strings.Contains(err.Error(), "safety cap 5") {
		t.Fatalf("refusal %v", err)
	}

	// A human's decision keeps its ticket in the count.
	e = newEnv(t, func(c *hubclient.Config) { c.RateN, c.MaxPending = 2, 100 })
	for i := range 2 {
		id, err := submitN(t, e, i)
		if err != nil {
			t.Fatal(err)
		}
		e.hub.DecideWith(id, ticket.Approved, "", nil, nil)
		if _, err := e.client.Poll(ctx, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := submitN(t, e, 2); rateErr(t, err).Limit != hubclient.LimitRate {
		t.Fatalf("refusal %v", err)
	}
}

func TestSetLimits(t *testing.T) {
	e := newEnv(t, func(c *hubclient.Config) { c.RateN = 1 })
	if _, err := submitN(t, e, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := submitN(t, e, 1); rateErr(t, err).Max != 1 {
		t.Fatal(err)
	}
	e.client.SetLimits(hubclient.Limits{RateN: 60})
	if l := e.client.Limits(); l.RateN != 60 || l.MaxPending != hubclient.MaxPending || l.RateWindow != hubclient.RateWindow {
		t.Fatalf("limits %+v", l)
	}
	if _, err := submitN(t, e, 1); err != nil {
		t.Fatalf("after SetLimits: %v", err)
	}
}
