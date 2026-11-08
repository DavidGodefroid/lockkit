package console

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/hubclient"
	"github.com/DavidGodefroid/lockkit/ipc"
)

// refusingApprover refuses every ticket with the error named by the
// decision's For.
type refusingApprover struct {
	errs map[string]error
}

func (r refusingApprover) Approve(context.Context, Decision) Result { return Result{} }
func (r refusingApprover) Mode() string                             { return HubApproval }
func (r refusingApprover) Submit(_ context.Context, d Decision) (Pending, error) {
	return Pending{}, r.errs[d.For]
}

// A ticket refused over the hub client's limits answers the agent with
// that ask's own limit, count and retry-after, however many asks run at
// once; a hub's 429 and other errors keep their general words.
func TestAskerRateLimitRefusal(t *testing.T) {
	errs := map[string]error{
		"rate":    &hubclient.RateLimitError{Limit: hubclient.LimitRate, Count: 30, Max: 30, Window: 5 * time.Minute, RetryAfter: 41500 * time.Millisecond},
		"total":   &hubclient.RateLimitError{Limit: hubclient.LimitTotal, Count: 300, Max: 300, Window: 5 * time.Minute, RetryAfter: 2 * time.Minute},
		"pending": fmt.Errorf("submit: %w", &hubclient.RateLimitError{Limit: hubclient.LimitPending, Count: 7, Max: 7, Window: 5 * time.Minute}),
		"hub429":  &hubclient.HubError{Status: http.StatusTooManyRequests, Code: "rate_limited", Message: "secret ticket text"},
		"other":   fmt.Errorf("boom"),
	}
	want := map[string][]string{
		"rate":    {"not submitted: too many tickets: 30 tickets for a human in 5m0s (limit 30, raised by limits.tickets_per_window); retry after 42s"},
		"total":   {"not submitted: too many tickets: 300 tickets in 5m0s", "safety cap 300", "retry after 2m0s"},
		"pending": {"not submitted: too many tickets: 7 tickets already pending (limit 7, raised by limits.max_pending); retry once one is decided"},
		"hub429":  {"too many requests are waiting for a decision"},
		"other":   {"could not be submitted for approval"},
	}
	a := Asker{IO: &fakeIO{}, Approver: refusingApprover{errs: errs}}
	const rounds = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	got := map[string][]string{}
	for i := range rounds {
		for name := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := a.Ask(context.Background(), int64(i), Ask{For: name}, func(audit.Base) {})
				if r.Refusal.Error == nil || r.Refusal.Error.Code != ipc.CodeInternal || r.Refusal.ID != int64(i) {
					t.Errorf("%s: refusal %+v", name, r.Refusal)
					return
				}
				mu.Lock()
				got[name] = append(got[name], r.Refusal.Error.Message)
				mu.Unlock()
			}()
		}
	}
	wg.Wait()
	for name, msgs := range got {
		if len(msgs) != rounds {
			t.Errorf("%s: %d answers, want %d", name, len(msgs), rounds)
		}
		for _, m := range msgs {
			for _, w := range want[name] {
				if !strings.Contains(m, w) {
					t.Errorf("%s: %q lacks %q", name, m, w)
				}
			}
			if strings.Contains(m, "hubclient:") || strings.Contains(m, "secret") {
				t.Errorf("%s: %q leaks", name, m)
			}
		}
	}
}
