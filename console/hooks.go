package console

import (
	"errors"
	"time"

	"github.com/DavidGodefroid/lockkit/config"
)

// Product hooks. A backend may implement any of the interfaces below to
// show its product's own wording and screens where the console's generic
// ones do not fit (a product that ported its own console onto this one
// keeps what its users and clients already see). A backend that implements
// none of them gets the console's own behaviour, unchanged.

// StatusView is what the console knows when it draws :status or the status
// row, for the product hooks that draw them.
type StatusView struct {
	// Status is the console's part of the status answer.
	Status StatusResult
	// Profile and Policy are the approved policy in force.
	Profile Profile
	Policy  Policy
	// Auto is auto mode in effect; ShowResults and AllowUnmask the other
	// switches.
	Auto, ShowResults, AllowUnmask bool
	// Pending: a loosening awaits :review. Requests counts the change
	// requests queued.
	Pending  bool
	Requests int
	// Boundary names the desktop boundary ("" in the session shape); Level
	// is the security level (2: every decision takes a finger).
	Boundary string
	Level    int
	// Session is the live session, nil while disconnected.
	Session Session
}

// StatusAnswerer is implemented by a backend that answers the status
// method itself: its StatusAnswer value is sent instead of StatusResult
// with Backend.Status under "product" (a product whose clients read a flat
// answer). c is the console's part; s is nil while disconnected.
type StatusAnswerer interface {
	StatusAnswer(c StatusResult, s Session) any
}

// StatusRower is implemented by a backend that lists its own :status rows
// (label, value; values escaped by the backend). The console aligns them.
type StatusRower interface {
	StatusRows(v StatusView) [][2]string
}

// StatusLiner is implemented by a backend that adds to the status row:
// Suffix follows the profile name, Parts come after the results switch.
type StatusLiner interface {
	StatusLineParts(v StatusView) (suffix string, parts []string)
}

// ChangeFormatter is implemented by a backend that renders a policy diff
// itself (at start, on a tightening and at :review). Every value must be
// escaped, as FormatChanges does.
type ChangeFormatter interface {
	FormatChanges(changes []config.Change) []string
}

// ConnectionComparer is implemented by a backend whose connection depends
// on more than Profile's Where, User, Host and Port (a TLS setting, a
// tunnel): a policy change for which ConnectionChanged reports true ends
// the session, as the open connection no longer matches the policy.
type ConnectionComparer interface {
	ConnectionChanged(old, next Policy) bool
}

// PolicyApplier is implemented by a backend that prepares itself for a
// policy before it is in force (compiles its rules): an error refuses the
// policy, which then is neither saved nor applied. NewServer calls it with
// the start policy.
type PolicyApplier interface {
	ApplyPolicy(p Policy) error
}

// Worder is implemented by a backend that words the console's lines in its
// product's terms (statements rather than requests). An empty field keeps
// the console's own text.
type Worder interface {
	Words() Words
}

// Words are the console lines a product may word itself. Each is the whole
// line, colours excepted; an empty one keeps the console's text.
type Words struct {
	// AutoStart is printed when the console starts in auto mode.
	AutoStart string
	// AutoOn and Manual are printed when the mode switches.
	AutoOn, Manual string
	// NoAutoProduction refuses auto mode on a production profile.
	NoAutoProduction string
	// NoAutoHub, when set, refuses auto mode in hub mode with this line
	// (the console otherwise accepts the switch, which has no effect there).
	NoAutoHub string
	// StatusAuto and StatusManual are the mode row of :status.
	StatusAuto, StatusManual string
	// ResultsOn is printed when the clear results are switched on;
	// StatusResults is their row of :status when on.
	ResultsOn, StatusResults string
	// UnmaskAsk is the question that allows unmasked output; UnmaskOff is
	// printed when it is turned off.
	UnmaskAsk, UnmaskOff string
	// ReviewAuto warns at :review that auto mode is on and the loosening
	// turns a production profile into another.
	ReviewAuto string
	// ChangeQueued words a change request from a client (already escaped).
	ChangeQueued func(change string) string
	// Reconnecting is printed before a reconnection.
	Reconnecting string
	// TTLReached is printed when credentials_ttl ends a connection.
	TTLReached func(ttl time.Duration, credentials string) string
	// ProductionChecks words the end of a session whose checks found
	// something once the profile became production: the console line and
	// the end reason.
	ProductionChecks func(p Profile, findings []Finding) (line, reason string)
	// ConnLost is the error a Handler gets from Env.Session when the
	// connection is lost and cannot be opened again.
	ConnLost string
}

// EndError, returned by ServerConfig.Reconnect (wrapped or not), ends the
// session with Reason.
type EndError struct {
	Reason string
	Err    error
}

func (e *EndError) Error() string { return e.Err.Error() }
func (e *EndError) Unwrap() error { return e.Err }

// endReason is the reason an EndError in err gives, if any.
func endReason(err error) (string, bool) {
	var e *EndError
	if errors.As(err, &e) {
		return e.Reason, true
	}
	return "", false
}

// AskerOf returns the Asker of the console behind env: a Handler that
// draws its own approval screen (prompts inside the frame, values to
// type) decides with it, so that a switch pressed meanwhile is refused and
// a missing finger ends the session as with Env.Approve.
func AskerOf(env Env) (Asker, bool) {
	if a, ok := env.(interface{ Asker() Asker }); ok {
		return a.Asker(), true
	}
	return Asker{}, false
}

// PolicyPendingOf reports a loosening awaiting :review in the console
// behind env.
func PolicyPendingOf(env Env) bool {
	if p, ok := env.(interface{ PolicyPending() bool }); ok {
		return p.PolicyPending()
	}
	return false
}

// words returns the backend's Words, or the zero value.
func (s *Server) words() Words {
	if w, ok := s.cfg.Backend.(Worder); ok {
		return w.Words()
	}
	return Words{}
}

// word returns w, or def when w is empty.
func word(w, def string) string {
	if w != "" {
		return w
	}
	return def
}

// formatChanges renders a policy diff with the backend's formatter.
func formatChangesOf(b Backend, changes []config.Change) []string {
	if f, ok := b.(ChangeFormatter); ok {
		return f.FormatChanges(changes)
	}
	return FormatChanges(changes)
}

// Asker returns the console's Asker (AskerOf).
func (s *Server) Asker() Asker { return s.asker() }

// statusView is what the status hooks see.
func (s *Server) statusView() StatusView {
	return StatusView{Status: s.Status(), Profile: s.profile, Policy: s.approved, Auto: s.autoApprove(),
		ShowResults: s.showResults, AllowUnmask: s.allowUnmask, Pending: s.pending != nil, Requests: len(s.requests),
		Boundary: s.cfg.Boundary, Level: s.cfg.Level, Session: s.sess}
}

// connectionChanged reports a change of the connection settings.
func (s *Server) connectionChanged(old Profile, oldP, next Policy) bool {
	if c, ok := s.cfg.Backend.(ConnectionComparer); ok {
		return c.ConnectionChanged(oldP, next)
	}
	n := next.Profile()
	return old.Where != n.Where || old.User != n.User || old.Host != n.Host || old.Port != n.Port
}

// Unwrap returns the backend's own session behind s: the console wraps a
// session whose login expires (a Vault lease), and a backend type-asserts
// what Unwrap returns to its own session type.
func Unwrap(s Session) Session {
	for {
		u, ok := s.(interface{ Unwrap() Session })
		if !ok {
			return s
		}
		s = u.Unwrap()
	}
}
