package hubclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// Recompute gives, for a stored plan, its policy fingerprint, plan hash
// and plan-hash inputs (ticket.InputDigests) as the lock sees them now: a
// renewal shows the human what moved since the expired ticket. A product
// sets it with SetRecompute; without one, a renewal keeps the plan's hash
// and says it was not checked (the run checks it anyway).
type Recompute func(p *plans.Plan) (policyFP, planHash string, inputs map[string]string, err error)

// SetRecompute sets the product's Recompute.
func (c *Client) SetRecompute(r Recompute) {
	c.mu.Lock()
	c.recompute = r
	c.mu.Unlock()
}

// OnRequest sets f, told of every hub request the lock acted on or
// refused (q nil when it did not verify), with the new ticket of a
// renewal: for the lock's audit and console.
func (c *Client) OnRequest(f func(q *ticket.HubRequest, renewal string, err error)) {
	c.mu.Lock()
	c.onRequest = f
	c.mu.Unlock()
}

// ErrBadRequest: a hub request that does not verify, is not for this
// lock, is stale, or names a facade the lock does not pin.
var ErrBadRequest = errors.New("hubclient: hub request refused")

// HandleRequests acts on the hub requests the last polls brought (Watch
// calls it after each Poll): a reveal seals the plan's clear screen to the
// facade's ephemeral key, a renewal asks again for an expired ticket. Each
// request is answered at the hub, once.
func (c *Client) HandleRequests(ctx context.Context, st *plans.Store) error {
	c.mu.Lock()
	reqs := c.requests
	c.requests = nil
	now := c.cfg.Now()
	for id, at := range c.seen {
		if now.Sub(at) > 2*ticket.RevealTTL {
			delete(c.seen, id)
		}
	}
	on := c.onRequest
	c.mu.Unlock()
	var errs []error
	for _, raw := range reqs {
		q, renewal, err := c.handle(ctx, st, raw)
		if q == nil && err == nil {
			continue // seen before
		}
		if on != nil {
			on(q, renewal, err)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// handle acts on one request; (nil, "", nil) for one already handled.
func (c *Client) handle(ctx context.Context, st *plans.Store, raw json.RawMessage) (*ticket.HubRequest, string, error) {
	q, err := ticket.VerifyHubRequest(c.cfg.HubKey, raw)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	if q.Instance != c.cfg.Instance || q.KeyID != ticket.KeyID(c.pub) {
		return nil, "", fmt.Errorf("%w: request %s is not for this instance", ErrBadRequest, q.ID)
	}
	c.mu.Lock()
	_, dup := c.seen[q.ID]
	if !dup {
		c.seen[q.ID] = c.cfg.Now()
	}
	c.mu.Unlock()
	if dup {
		return nil, "", nil
	}
	if !q.Fresh(c.cfg.Now()) {
		// Not answered: the hub gave up on it already.
		return q, "", fmt.Errorf("%w: request %s is stale", ErrBadRequest, q.ID)
	}
	var body []byte
	renewal := ""
	switch q.Kind {
	case ticket.RequestReveal:
		var a *ticket.RevealAnswer
		if a, err = c.reveal(st, q); err == nil {
			var ab []byte
			if ab, err = a.Marshal(); err == nil {
				// Verbatim: the facade checks the lock's signature over
				// these canonical bytes.
				body = append(append([]byte(`{"reveal":`), ab...), '}')
			}
		}
	case ticket.RequestRenew:
		var p *plans.Plan
		p, err = st.TicketPlan(q.Ticket)
		if err == nil {
			renewal, err = c.renew(ctx, st, p, plans.OwnerOf(p))
		}
		if err == nil {
			body, _ = json.Marshal(struct {
				Ticket string `json:"ticket"`
			}{renewal})
		}
	}
	if err != nil {
		body, _ = json.Marshal(struct {
			Error string `json:"error"`
		}{strings.ToValidUTF8(cut(err.Error(), 512), "")})
	}
	if aerr := c.do(ctx, http.MethodPost, "/v1/requests/"+url.PathEscape(q.ID)+"/answer", body, true, nil); aerr != nil {
		err = errors.Join(err, fmt.Errorf("request %s: the answer did not reach the hub: %w", q.ID, aerr))
	}
	return q, renewal, err
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// reveal seals the clear screen of q's ticket to the facade's key, if a
// pinned facade signed it and the ticket's plan is pending with a clear
// screen.
func (c *Client) reveal(st *plans.Store, q *ticket.HubRequest) (*ticket.RevealAnswer, error) {
	if len(c.cfg.Facades) == 0 {
		return nil, fmt.Errorf("%w: this lock pins no facade key (--facade-keys-file)", ErrBadRequest)
	}
	epk, err := q.Reveal.Verify(c.cfg.Facades)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	p, err := st.TicketPlan(q.Ticket)
	if err != nil {
		return nil, err
	}
	switch {
	case p.State != plans.Pending:
		return nil, fmt.Errorf("ticket %s is %s: nothing to reveal", q.Ticket, p.State)
	case p.Clear == nil:
		return nil, fmt.Errorf("ticket %s: the lock kept no clear screen", q.Ticket)
	}
	return ticket.SealReveal(c.cfg.Key, q, epk, *p.Clear)
}

// ErrNotRenewable: the ticket cannot be renewed (not expired, or gone).
var ErrNotRenewable = errors.New("hubclient: ticket cannot be renewed")

// Renew asks again for the expired ticket ticketID of caller (decision
// H1): a new ticket for the same plan, re-checked now (SetRecompute), that
// says what changed in its plan-hash inputs. It returns the new ticket;
// a ticket renewed already returns its renewal. The agent runs the new
// ticket once it is decided.
func (c *Client) Renew(ctx context.Context, st *plans.Store, ticketID string, caller plans.Caller) (string, error) {
	p, err := st.ExpiredByTicket(ticketID, caller)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNotRenewable, err)
	}
	return c.renew(ctx, st, p, caller)
}

func (c *Client) renew(ctx context.Context, st *plans.Store, old *plans.Plan, caller plans.Caller) (string, error) {
	if old.State != plans.Expired && old.RenewedBy == "" {
		return "", fmt.Errorf("%w: ticket %s is %s", ErrNotRenewable, old.Ticket, old.State)
	}
	own, err := old.LockTicket(c.pub)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	rc := c.recompute
	c.mu.Unlock()
	fp, hash := old.Binding.PolicyFP, old.Binding.PlanHash
	var inputs map[string]string
	checked := rc != nil
	if rc != nil {
		if fp, hash, inputs, err = rc(old); err != nil {
			return "", fmt.Errorf("%w: the plan could not be checked again: %v", ErrNotRenewable, err)
		}
	}
	n, err := st.Renew(old.ID, fp, hash, inputs)
	if errors.Is(err, plans.ErrRenewed) {
		if n.State == plans.Planned {
			// A renewal that did not reach the pending state: submit it now.
			return c.submitRenewal(ctx, st, n, caller, own, old, nil, checked)
		}
		if n.Ticket == "" {
			return "", fmt.Errorf("%w: renewal plan %s is %s", ErrNotRenewable, n.ID, n.State)
		}
		return n.Ticket, nil
	}
	if err != nil {
		return "", err
	}
	var changes []ticket.Change
	if checked {
		before, after := old.Binding.Inputs, inputs
		if before == nil || after == nil {
			before, after = map[string]string{"plan_hash": old.Binding.PlanHash}, map[string]string{"plan_hash": hash}
		}
		before, after = with(before, "policy_fp", old.Binding.PolicyFP), with(after, "policy_fp", fp)
		changes = ticket.DiffInputs(before, after)
	}
	return c.submitRenewal(ctx, st, n, caller, own, old, changes, checked)
}

// with is m with k set to v unless m has k.
func with(m map[string]string, k, v string) map[string]string {
	if _, ok := m[k]; ok {
		return m
	}
	out := make(map[string]string, len(m)+1)
	for a, b := range m {
		out[a] = b
	}
	out[k] = v
	return out
}

func (c *Client) submitRenewal(ctx context.Context, st *plans.Store, n *plans.Plan, caller plans.Caller, own *ticket.Ticket, old *plans.Plan, changes []ticket.Change, checked bool) (string, error) {
	t := ticket.NewTicket(ticket.Source{Lock: own.Source.Lock}, own.Risk, n.Binding.PlanHash, n.Binding.PolicyFP, c.cfg.Now(),
		ticket.ClampTTL(own.Risk, c.cfg.ApprovalTTL))
	t.Workspace, t.Requester, t.Flags = own.Workspace, own.Requester, own.Flags
	reason := ticket.RenewExpired
	if old.ApprovedAt != nil {
		reason = ticket.RenewApprovalExpired
	}
	r := &ticket.Renewal{Of: own.ID, Reason: reason, Checked: checked, Changes: changes}
	if old.ApprovedAt != nil {
		a := old.ApprovedAt.UTC().Truncate(1e6)
		r.ApprovedAt = &a
	}
	t.Renews = r
	// The expired ticket's screen is the masked one the lock signed
	// (LockTicket verified it): it leaves again as it left.
	return c.submit(ctx, st, n.ID, caller, t, own.Screen, own.PII.Touched, n.Clear)
}
