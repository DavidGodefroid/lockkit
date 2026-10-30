package hubclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/DavidGodefroid/lockkit/plans"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// Recompute gives, for a stored plan, its policy fingerprint, plan hash
// and plan-hash inputs (ticket.InputDigests) as the lock sees them now: a
// renewal shows the human what moved since the expired ticket. An input it
// cannot check now (no session) is ticket.UncheckedInput, never its stored
// digest: the renewal then says so, and is not one click; keep the stored
// plan hash in that case (the run checks it). A product
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
	if q.Reveal != nil {
		// A reveal key is one use, whatever request carries it.
		if _, ok := c.seen["reveal:"+q.Reveal.ID]; ok {
			dup = true
		}
	}
	if !dup {
		c.seen[q.ID] = c.cfg.Now()
		if q.Reveal != nil {
			c.seen["reveal:"+q.Reveal.ID] = c.cfg.Now()
		}
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
			p, err = c.ageOut(st, p)
		}
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
		// A fixed code only: the error text may hold what the hub must not
		// see (a recheck's plan inputs, SQL, paths). The detail stays with
		// the lock (OnRequest: its audit and console).
		body, _ = json.Marshal(struct {
			Error string `json:"error"`
		}{AnswerCode(err)})
	}
	if aerr := c.do(ctx, http.MethodPost, "/v1/requests/"+url.PathEscape(q.ID)+"/answer", body, true, nil); aerr != nil {
		err = errors.Join(err, fmt.Errorf("request %s: the answer did not reach the hub: %w", q.ID, aerr))
	}
	return q, renewal, err
}

// Answer codes: the only error text a lock sends the hub for a request.
const (
	CodeFacadeRefused = "facade_refused" // no pinned facade, or not this one
	CodeNotPending    = "not_pending"    // nothing to reveal: the ticket is not pending
	CodeNoClear       = "no_clear_screen"
	CodeNotRenewable  = "not_renewable" // not expired, or gone
	CodeRecheckFailed = "recheck_failed"
	CodePolicyChanged = "policy_changed" // plan again
	CodeLimited       = "rate_limited"
	CodeFailed        = "failed"
)

// AnswerCode is the code a lock answers the hub for a request that failed
// with err.
func AnswerCode(err error) string {
	switch {
	case errors.Is(err, errRecheck):
		return CodeRecheckFailed
	case errors.Is(err, errPolicyChanged):
		return CodePolicyChanged
	case errors.Is(err, ErrBadRequest), errors.Is(err, ticket.ErrFacade):
		return CodeFacadeRefused
	case errors.Is(err, errNotPending):
		return CodeNotPending
	case errors.Is(err, errNoClear):
		return CodeNoClear
	case errors.Is(err, ErrNotRenewable), errors.Is(err, plans.ErrNoSuchPlan), errors.Is(err, plans.ErrNotExpired):
		return CodeNotRenewable
	case errors.Is(err, ErrRateLimited):
		return CodeLimited
	}
	return CodeFailed
}

var (
	errRecheck    = errors.New("the plan could not be checked again")
	errNotPending = errors.New("nothing to reveal")
	errNoClear    = errors.New("the lock kept no clear screen")
)

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
		return nil, fmt.Errorf("%w: ticket %s is %s", errNotPending, q.Ticket, p.State)
	case p.Clear == nil:
		return nil, fmt.Errorf("%w: ticket %s", errNoClear, q.Ticket)
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
	// One renewal at a time: the agent's run and the human's request may
	// race on the same expired plan.
	c.renewMu.Lock()
	defer c.renewMu.Unlock()
	return c.renewLocked(ctx, st, old, caller)
}

func (c *Client) renewLocked(ctx context.Context, st *plans.Store, old *plans.Plan, caller plans.Caller) (string, error) {
	if old.State != plans.Expired {
		return "", fmt.Errorf("%w: ticket %s is %s", ErrNotRenewable, old.Ticket, old.State)
	}
	own, err := old.LockTicket(c.pub)
	if err != nil {
		return "", err
	}
	if old.RenewedBy == "" {
		c.mu.Lock()
		rc := c.recompute
		c.mu.Unlock()
		fp, hash := old.Binding.PolicyFP, old.Binding.PlanHash
		var inputs map[string]string
		if rc != nil {
			if fp, hash, inputs, err = rc(old); err != nil {
				return "", fmt.Errorf("%w: %w: %v", ErrNotRenewable, errRecheck, err)
			}
			if fp != old.Binding.PolicyFP {
				// The risk class and the flags came from the old policy:
				// a new one may ask more of the human. Plan again.
				return "", fmt.Errorf("%w: %w: the policy changed since the plan", ErrNotRenewable, errPolicyChanged)
			}
		}
		if _, err := st.Renew(old.ID, fp, hash, inputs, rc != nil); err != nil && !errors.Is(err, plans.ErrRenewed) {
			return "", err
		}
	}
	n, err := st.RenewalOf(old.ID) // the renewal, as stored
	if err != nil {
		return "", err
	}
	if n.Ticket != "" {
		// Through a lookup: a renewal past its own expiry reads Expired.
		if x, err := st.TicketPlan(n.Ticket); err == nil {
			n = x
		}
	}
	switch n.State {
	case plans.Planned:
	case plans.Pending:
		return n.Ticket, nil
	case plans.Expired:
		// The renewal expired too: renew it in turn (a chain, one link at
		// a time; renewMu is held, so call the unlocked body).
		if n.Ticket == "" {
			return "", fmt.Errorf("%w: renewal plan %s is %s", ErrNotRenewable, n.ID, n.State)
		}
		// Same binding as old: the same caller.
		return c.renewLocked(ctx, st, n, caller)
	default:
		// Ran, denied, withdrawn, stale: nothing left to ask again.
		return "", fmt.Errorf("%w: its renewal %s is %s", ErrNotRenewable, n.Ticket, n.State)
	}
	// Planned: new, or a renewal whose submission failed (hub limits). Its
	// changes come from the stored bindings, whichever call submits it.
	return c.submitRenewal(ctx, st, n, caller, own, old)
}

var errPolicyChanged = errors.New("policy changed")

// renewalChanges are the plan-hash inputs that moved, by name, from what
// the human last approved in the renewal chain (the newest link with an
// approval, else the chain's first plan) to n: a link that was never
// approved does not reset what "changed" means. checked is false when n
// was not checked, or a link of the chain is gone (pruned).
func renewalChanges(st *plans.Store, old, n *plans.Plan) (changes []ticket.Change, checked bool) {
	if !n.RenewChecked {
		return nil, false
	}
	base := old
	for i := 0; base.ApprovedAt == nil && base.Renews != ""; i++ {
		prev, err := st.PlanByID(base.Renews)
		if err != nil || i >= plans.MaxPlans {
			return nil, false
		}
		base = prev
	}
	before, after := base.Binding.Inputs, n.Binding.Inputs
	if before == nil || after == nil {
		before, after = map[string]string{"plan_hash": base.Binding.PlanHash}, map[string]string{"plan_hash": n.Binding.PlanHash}
	}
	return ticket.DiffInputs(before, after), true
}

func (c *Client) submitRenewal(ctx context.Context, st *plans.Store, n *plans.Plan, caller plans.Caller, own *ticket.Ticket, old *plans.Plan) (string, error) {
	t := ticket.NewTicket(ticket.Source{Lock: own.Source.Lock}, own.Risk, n.Binding.PlanHash, n.Binding.PolicyFP, c.cfg.Now(),
		ticket.ClampTTL(own.Risk, c.cfg.ApprovalTTL))
	t.Workspace, t.Requester, t.Flags = own.Workspace, own.Requester, own.Flags
	changes, checked := renewalChanges(st, old, n)
	r := &ticket.Renewal{Of: own.ID, Reason: ticket.RenewExpired, Checked: checked, Changes: changes}
	if old.ApprovedAt != nil {
		a := old.ApprovedAt.UTC().Truncate(time.Millisecond)
		r.Reason, r.ApprovedAt = ticket.RenewApprovalExpired, &a
	}
	t.Renews = r
	// The expired ticket's screen is the masked one the lock signed
	// (LockTicket verified it): it leaves again as it left.
	return c.submit(ctx, st, n.ID, caller, t, own.Screen, own.PII.Touched, n.Clear)
}

// ageOut ends Expired a pending plan whose approval is too old to be used
// (what Begin would do at the agent's run), so that the human can renew it
// before the agent comes back. Any other plan comes back as it is.
func (c *Client) ageOut(st *plans.Store, p *plans.Plan) (*plans.Plan, error) {
	if p.State != plans.Pending {
		return p, nil
	}
	c.mu.Lock()
	e, ok := c.inbox[p.Ticket]
	c.mu.Unlock()
	if !ok {
		return p, nil
	}
	d, err := c.verify(e)
	if err != nil || d.Decision != ticket.Approved {
		return p, nil
	}
	own, err := p.LockTicket(c.pub)
	if err != nil || d.Match(own) != nil {
		return p, nil
	}
	// Every check Begin makes before it would expire the approval: only
	// an approval Begin would have honoured may age into a renewal that
	// says it was approved.
	if d.Device != nil || d.Facade == ticket.FacadeMobile {
		if c.verifyDevice(d, p.SignedTicket) != nil {
			return p, nil
		}
	}
	if d.Device == nil && c.needsDevice(own.Risk) {
		return p, nil
	}
	uerr := d.Usable(own, c.cfg.Now(), ticket.ClampTTL(own.Risk, c.cfg.ApprovalTTL))
	if !errors.Is(uerr, ticket.ErrExpired) {
		return p, nil
	}
	owner := plans.OwnerOf(p)
	if err := st.ExpireApproval(p.ID, owner, d.At, uerr.Error()); err != nil {
		if !errors.Is(err, plans.ErrState) {
			return nil, err
		}
		// Moved meanwhile (the agent's run, another request): as it is now.
		return st.TicketPlan(p.Ticket)
	}
	c.drop(p.Ticket)
	return st.TicketPlan(p.Ticket)
}
