package hubclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/DavidGodefroid/lockkit/render"
	"github.com/DavidGodefroid/lockkit/ticket"
)

// Ask pushes a connect ticket and waits for the hub's decision on it,
// until ctx ends: what lazyconn asks before opening a backend connection.
// A connect ticket is the lock's own (it runs no plan of an agent), so it
// is not recorded in a plans.Store and is never resent after a restart:
// a lock that restarts starts disconnected and asks again.
//
// t is a ticket.KindConnect ticket (ticket.NewConnectTicket); Ask sets its
// instance, key id, screen and touched kinds from screen, signs it and
// pushes it. The decision comes back verified under the pinned hub key,
// for this instance and key, matching t (ticket.Decision.Match), with a
// device's signature over the ticket checked when the decision names one;
// a denial comes back as a decision too. The caller checks Usable, and
// opens the secret with the ticket's one-use key (Decision.OpenSecret).
//
// Ask polls the hub itself, or waits for a concurrent Watch to: either
// way the decision is taken from the client's inbox, once.
func (c *Client) Ask(ctx context.Context, t *ticket.Ticket, screen render.MaskedScreen) (*ticket.Decision, error) {
	if !screen.Valid() {
		return nil, render.ErrUnmasked
	}
	if t.Kind != ticket.KindConnect {
		return nil, fmt.Errorf("hubclient: Ask takes a connect ticket, not %q (the others go through Submit and a plan)", t.Kind)
	}
	c.mu.Lock()
	now := c.cfg.Now()
	kept := c.recent[:0]
	for _, at := range c.recent {
		if now.Sub(at) < c.cfg.RateWindow {
			kept = append(kept, at)
		}
	}
	c.recent = kept
	if len(c.recent) >= c.cfg.RateN {
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: %d new tickets in %s", ErrRateLimited, c.cfg.RateN, c.cfg.RateWindow)
	}
	c.recent = append(c.recent, now)
	c.mu.Unlock()

	t.Source.Instance, t.Source.KeyID = c.cfg.Instance, ticket.KeyID(c.pub)
	t.Screen, t.PII.Touched = screen.Screen(), screen.Touched()
	if err := t.Sign(c.cfg.Key); err != nil {
		return nil, err
	}
	signed, err := t.Marshal()
	if err != nil {
		return nil, err
	}
	backoff := time.Second
	for {
		err := c.pushRaw(ctx, t.ID, signed)
		if err == nil {
			break
		}
		if !errors.Is(err, ErrUnreachable) {
			return nil, err
		}
		if werr := sleepCtx(ctx, backoff); werr != nil {
			return nil, errors.Join(werr, err)
		}
		backoff = min(backoff*2, MaxWait)
	}
	defer c.drop(t.ID)
	backoff = time.Second
	for {
		c.mu.Lock()
		e, ok := c.inbox[t.ID]
		wake := c.wake
		c.mu.Unlock()
		if ok {
			return c.askDecision(e, t, signed)
		}
		if c.pollMu.TryLock() {
			c.pollMu.Unlock()
			_, err := c.Poll(ctx, MaxWait/2)
			switch {
			case err == nil, errors.Is(err, ErrBadDecision):
				backoff = time.Second
				continue
			case ctx.Err() != nil:
				return nil, ctx.Err()
			case !errors.Is(err, ErrUnreachable):
				return nil, err
			}
			if werr := sleepCtx(ctx, backoff); werr != nil {
				return nil, errors.Join(werr, err)
			}
			backoff = min(backoff*2, MaxWait)
			continue
		}
		// Another poll (Watch) is under way: its decisions wake us.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-wake:
		case <-time.After(time.Second):
		}
	}
}

// askDecision checks the decision e on the lock's own ticket t, signed as
// signed.
func (c *Client) askDecision(e entry, t *ticket.Ticket, signed []byte) (*ticket.Decision, error) {
	d, err := c.verify(e)
	if err != nil {
		return nil, err
	}
	if err := d.Match(t); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadDecision, err)
	}
	if d.Device != nil || d.Facade == ticket.FacadeMobile {
		if err := c.verifyDevice(d, signed); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadDecision, err)
		}
	}
	if d.Decision == ticket.Approved && d.Device == nil && c.needsDevice(t.Risk) {
		return nil, fmt.Errorf("%w: %w: a %s approval must be signed by a pinned device; this one came from facade %q",
			ErrBadDecision, ticket.ErrDevice, t.Risk, d.Facade)
	}
	return d, nil
}

// Consumed tells the hub that the decision on ticket id was acted on (a
// connect ticket: the connection is open).
func (c *Client) Consumed(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/tickets/"+url.PathEscape(id)+"/consumed", nil, true, nil)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
