package console

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/confine"
	"github.com/DavidGodefroid/lockkit/ipc"
)

// The confined agent check (lockkit#133). Every client connection reports
// its confinement in hello (ipc.Confinement, the client's self-check); the
// console adds what the kernel says of the peer (a group owning a runtime
// socket, RuntimeGIDs) and decides:
//
//	reported confined, no runtime group       → served
//	unconfined, profile without unconfined    → refused (CodeUnconfined)
//	unconfined, unconfined = true, not prod   → served, banner, audited unconfined
//	unconfined, production or managed require → refused
//
// A hello without a report (an older client) is unconfined (old_client).
// On a socket connection no method is served before an accepted hello, and
// the decision is taken again at every request: a policy that becomes
// production, or a managed file that comes to require a confined agent,
// cuts an unconfined connection already open.

// DecisionRefusedUnconfined is the decision of the record of a request
// refused because its agent does not run confined.
const DecisionRefusedUnconfined = "refused-unconfined"

// UnconfinedBanner is printed at start and at every unconfined connection
// when the profile accepts unconfined agents.
const UnconfinedBanner = "unconfined: this lock protects against mistakes, not against a compromised agent"

// maxReasons bounds the reason codes taken from a client.
const maxReasons = 8

// connState is one client connection's state, set by Loop.accept.
type connState struct {
	helloed    bool
	unconfined bool
	reasons    []string
}

type connKey struct{}

// withConn returns ctx carrying a new connection state.
func withConn(ctx context.Context) context.Context {
	return context.WithValue(ctx, connKey{}, &connState{})
}

func connFrom(ctx context.Context) *connState {
	c, _ := ctx.Value(connKey{}).(*connState)
	return c
}

// unconfinedOf returns whether the request of ctx comes from an unconfined
// connection, and its reasons.
func unconfinedOf(ctx context.Context) (bool, []string) {
	if c := connFrom(ctx); c != nil && c.unconfined {
		return true, c.reasons
	}
	return false, nil
}

// confinementReasons are the reasons a hello's client is unconfined: those
// it reports (known codes only: the text is the agent's), runtime_group
// when the kernel says the peer holds one of runtimeGIDs, old_client when
// it sent no report. None: confined.
func confinementReasons(c *ipc.Confinement, cred ipc.Cred, credOK bool, runtimeGIDs []int) []string {
	var out []string
	add := func(code string) {
		if !slices.Contains(out, code) && len(out) < maxReasons {
			out = append(out, code)
		}
	}
	switch {
	case c == nil:
		add(confine.OldClient)
	case !c.Confined:
		for _, r := range c.Reasons {
			if confine.Known(r) && r != confine.RuntimeGroup && r != confine.OldClient {
				add(r)
			}
		}
		if len(out) == 0 {
			// Unconfined by its own word, without a reason we know.
			add(confine.InContainer)
		}
	}
	if credOK && cred.HasGroup(runtimeGIDs) {
		add(confine.RuntimeGroup)
	}
	return out
}

// unconfinedAllowed reports whether the policy in force serves an
// unconfined agent; when not, why is "" for a profile without
// unconfined = true, else why it may not have it.
func (s *Server) unconfinedAllowed() (ok bool, why string) {
	switch {
	case s.managed.RequireConfinedAgent():
		return false, "the company's managed configuration requires a confined agent"
	case s.profile.Production:
		return false, "unconfined is never allowed on a production profile"
	}
	return s.profile.Unconfined, ""
}

// unconfinedMessage is the client's error text of a refusal.
func unconfinedMessage(reasons []string, why string) string {
	parts := make([]string, len(reasons))
	for i, r := range reasons {
		parts[i] = r + ": " + confine.Text(r)
	}
	msg := "refused: this agent does not run confined (" + strings.Join(parts, "; ") + "); run it inside lea"
	if why == "" {
		return msg + ", or ask the human to set unconfined = true on this non-production profile"
	}
	return msg + " (" + why + ")"
}

// checkConfinement decides the request req of an unconfined or not yet
// greeted connection: nil serves it, else the refusal.
func (s *Server) checkConfinement(ctx context.Context, req ipc.Request) *ipc.Response {
	c := connFrom(ctx)
	if c == nil || req.Method == ipc.MethodHello {
		return nil
	}
	if !c.helloed {
		r := ErrResp(req.ID, ipc.CodeInvalidRequest, "hello first: the console serves a connection once its hello is accepted")
		return &r
	}
	if !c.unconfined {
		return nil
	}
	if ok, why := s.unconfinedAllowed(); !ok {
		c.helloed = false
		return s.refuseUnconfined(ctx, req, c.reasons, why)
	}
	return nil
}

// refuseUnconfined audits and answers the refusal of an unconfined agent.
func (s *Server) refuseUnconfined(ctx context.Context, req ipc.Request, reasons []string, why string) *ipc.Response {
	msg := unconfinedMessage(reasons, why)
	if why == "" {
		why = "the profile does not set unconfined = true"
	}
	_ = s.record(ctx, audit.Base{Event: audit.EventRefused, Decision: DecisionRefusedUnconfined, Error: why,
		Unconfined: true, UnconfinedReasons: reasons})
	s.println(Paint.Fail("refused an unconfined agent (" + strings.Join(reasons, ", ") + "): " + why))
	r := ErrResp(req.ID, ipc.CodeUnconfined, msg)
	return &r
}

// greet takes the confinement decision of a hello whose protocol is
// accepted: nil serves the connection, else the refusal.
func (s *Server) greet(ctx context.Context, req ipc.Request, p ipc.HelloParams) *ipc.Response {
	c := connFrom(ctx)
	if c == nil {
		// Not a socket connection (an in-process call): nothing to decide.
		return nil
	}
	cred, credOK := PeerFrom(ctx)
	reasons := confinementReasons(p.Confinement, cred, credOK, s.cfg.RuntimeGIDs)
	c.helloed, c.unconfined, c.reasons = false, len(reasons) > 0, reasons
	if !c.unconfined {
		c.helloed = true
		return nil
	}
	if ok, why := s.unconfinedAllowed(); !ok {
		return s.refuseUnconfined(ctx, req, reasons, why)
	}
	c.helloed = true
	s.println(Paint.Fail(UnconfinedBanner + " (" + strings.Join(reasons, ", ") + ")"))
	return nil
}

// stampUnconfined marks b as a record of an unconfined connection.
func stampUnconfined(ctx context.Context, b *audit.Base) {
	if u, reasons := unconfinedOf(ctx); u {
		b.Unconfined, b.UnconfinedReasons = true, reasons
	}
}

// ParseGIDs parses --runtime-gids: comma-separated gids ("" is none).
func ParseGIDs(v string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(v, ",") {
		if f == "" && v == "" {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(f), 10, 31)
		if err != nil {
			return nil, fmt.Errorf("%w: --runtime-gids is not a comma-separated list of gids", ErrConfig)
		}
		out = append(out, int(n))
	}
	return out, nil
}
