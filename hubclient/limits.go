package hubclient

import (
	"fmt"
	"time"
)

// Limits bound the tickets a lock opens. The rate is there to keep an
// agent from flooding the human with questions, not to slow the reads that
// need nobody: a ticket an auto rule decided (`lox run`'s default:read,
// session:connect, ...) leaves RateN's count once its decision comes back,
// and only RateTotal, a high safety cap against a runaway agent, still
// counts it.
type Limits struct {
	// MaxPending bounds the pending tickets of an instance
	// (limits.max_pending).
	MaxPending int
	// RateN tickets a human decides per RateWindow at most
	// (limits.tickets_per_window, limits.ticket_window).
	RateN      int
	RateWindow time.Duration
	// RateTotal tickets per RateWindow at most, auto-decided ones
	// included (never below RateN).
	RateTotal int
}

// DefaultLimits are the limits of a lock that sets none.
func DefaultLimits() Limits {
	return Limits{MaxPending: MaxPending, RateN: RateN, RateWindow: RateWindow, RateTotal: RateTotal}
}

// Effective is l with each field <= 0 replaced by its default, and
// RateTotal raised to RateN when below it.
func (l Limits) Effective() Limits {
	d := DefaultLimits()
	if l.MaxPending <= 0 {
		l.MaxPending = d.MaxPending
	}
	if l.RateN <= 0 {
		l.RateN = d.RateN
	}
	if l.RateWindow <= 0 {
		l.RateWindow = d.RateWindow
	}
	if l.RateTotal <= 0 {
		l.RateTotal = d.RateTotal
	}
	l.RateTotal = max(l.RateTotal, l.RateN)
	return l
}

// Which limit a RateLimitError names.
const (
	LimitPending = "max_pending"
	LimitRate    = "tickets_per_window"
	LimitTotal   = "total"
)

// RateLimitError is a ticket the lock refused to open: it names the limit,
// the current count and when the next ticket will be accepted. It is
// ErrRateLimited.
type RateLimitError struct {
	// Limit is LimitPending, LimitRate or LimitTotal.
	Limit string
	// Count is the current count, Max the limit.
	Count, Max int
	Window     time.Duration
	// RetryAfter is when a ticket will be accepted again; 0 for
	// LimitPending: once a pending ticket is decided.
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	switch e.Limit {
	case LimitPending:
		return fmt.Sprintf("%v: %d tickets already pending (limit %d, raised by limits.max_pending); retry once one is decided",
			ErrRateLimited, e.Count, e.Max)
	case LimitTotal:
		return fmt.Sprintf("%v: %d tickets in %s, auto-decided ones included (safety cap %d); retry after %s",
			ErrRateLimited, e.Count, e.Window, e.Max, retryText(e.RetryAfter))
	}
	return fmt.Sprintf("%v: %d tickets for a human in %s (limit %d, raised by limits.tickets_per_window); retry after %s",
		ErrRateLimited, e.Count, e.Window, e.Max, retryText(e.RetryAfter))
}

// Is makes a RateLimitError ErrRateLimited.
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// retryText is d rounded up to the second ("42s").
func retryText(d time.Duration) string {
	return (d + time.Second - 1).Truncate(time.Second).String()
}

// sent is a ticket opened in the rate window.
type sent struct {
	at   time.Time
	id   string
	auto bool // an auto rule decided it: out of RateN's count
}

// SetLimits replaces the client's limits (a profile reloaded after its
// review); fields <= 0 take the defaults. The tickets already counted stay
// counted.
func (c *Client) SetLimits(l Limits) {
	c.mu.Lock()
	c.limits = l.Effective()
	c.mu.Unlock()
}

// Limits returns the client's limits, defaults applied.
func (c *Client) Limits() Limits {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.limits
}

// admit counts ticket id against the limits, pending being the tickets
// already pending; it returns a *RateLimitError when one is reached. c.mu
// is held.
func (c *Client) admit(id string, pending int) error {
	l := c.limits
	now := c.cfg.Now()
	kept := c.recent[:0]
	asked := 0
	var oldest, oldestAsked time.Time
	for _, s := range c.recent {
		if now.Sub(s.at) >= l.RateWindow {
			continue
		}
		kept = append(kept, s)
		if oldest.IsZero() {
			oldest = s.at
		}
		if !s.auto {
			if asked == 0 {
				oldestAsked = s.at
			}
			asked++
		}
	}
	c.recent = kept
	switch {
	case len(c.recent) >= l.RateTotal:
		return &RateLimitError{Limit: LimitTotal, Count: len(c.recent), Max: l.RateTotal, Window: l.RateWindow,
			RetryAfter: oldest.Add(l.RateWindow).Sub(now)}
	case asked >= l.RateN:
		return &RateLimitError{Limit: LimitRate, Count: asked, Max: l.RateN, Window: l.RateWindow,
			RetryAfter: oldestAsked.Add(l.RateWindow).Sub(now)}
	case pending >= l.MaxPending:
		return &RateLimitError{Limit: LimitPending, Count: pending, Max: l.MaxPending, Window: l.RateWindow}
	}
	c.recent = append(c.recent, sent{at: now, id: id})
	return nil
}

// decidedAuto takes ticket id out of RateN's count: an auto rule decided
// it. c.mu is held.
func (c *Client) decidedAuto(id string) {
	for i := range c.recent {
		if c.recent[i].id == id {
			c.recent[i].auto = true
		}
	}
}
