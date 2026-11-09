package console

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/DavidGodefroid/lockkit/audit"
	"github.com/DavidGodefroid/lockkit/kit"
	"github.com/DavidGodefroid/lockkit/managed"
	"github.com/DavidGodefroid/lockkit/sanitize"
)

// ManagedBackend is implemented by a backend whose policy the company's
// managed file bounds (package managed): its [<product>.bounds] section.
// A backend that does not implement it refuses to start when the managed
// file has a section for it, rather than run unbounded.
type ManagedBackend interface {
	// ManagedBounds returns the bounds m sets on p: managed.Bounds with
	// p at its ceiling, or a nil Ceiling when m bounds nothing of p. An
	// error (an invalid bounds section) refuses p. m is never nil.
	ManagedBounds(p Policy, m *managed.File) (managed.Bounds, error)
}

// ErrManaged is a start refused by the company's managed configuration:
// the file is unreadable, badly owned or badly signed, or the policy goes
// beyond its bounds. No human can approve past it.
var ErrManaged = errors.New("console: refused by the company's managed configuration")

// DecisionRefusedManaged is the decision of a policy record refused by
// the managed file: never pending, never approvable.
const DecisionRefusedManaged = "refused-managed"

// DecisionManagedChanged is the decision of the policy record made when
// the managed file changes while the console runs; the record carries the
// new fingerprint.
const DecisionManagedChanged = "managed-changed"

// managedFP is the fingerprint of m, "" for none.
func managedFP(m *managed.File) string {
	if m == nil {
		return ""
	}
	return m.Fingerprint
}

// managedViolations checks p against m's bounds through the backend.
func managedViolations(p kit.Product, b Backend, pol Policy, m *managed.File) ([]managed.Violation, error) {
	if m == nil {
		return nil, nil
	}
	mb, ok := b.(ManagedBackend)
	if !ok {
		if m.Has(p.Name) {
			return nil, fmt.Errorf("the managed file has a [%s] section, but this version of %s does not apply it: update %s", p.Name, p.Name, p.Name)
		}
		return nil, nil
	}
	bounds, err := mb.ManagedBounds(pol, m)
	if err != nil {
		return nil, err
	}
	if bounds.Tool == "" {
		bounds.Tool = p.Name
	}
	if bounds.Profile == "" {
		bounds.Profile = pol.Profile().Name
	}
	return managed.Check(pol, bounds), nil
}

// violationLines are the lines that tell the human why a policy is
// refused: one per violation, or the error.
func violationLines(vs []managed.Violation, err error) []string {
	if err != nil {
		return []string{"blocked by company policy: " + err.Error()}
	}
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.String())
	}
	return out
}

// checkManaged re-reads the managed file at a policy poll. It returns
// false when the poll must stop here: the session ended (the file became
// unreadable, or the policy in force is beyond a stricter file) or the
// policy was just adopted. A file that changed is recorded; the policy in
// force beyond it is replaced at once by the files' policy when that one
// is within the bounds and only tightens, else the session ends.
func (s *Server) checkManaged() bool {
	if s.cfg.loadManaged == nil {
		return true
	}
	m, err := s.cfg.loadManaged(context.Background())
	if err != nil {
		_ = s.record(context.Background(), audit.Base{Event: audit.EventPolicy, Decision: DecisionRefusedManaged, Error: err.Error()})
		s.println(red + "the company's managed configuration cannot be read: " + sanitize.Terminal(err.Error(), false) + "; the session ends" + reset)
		s.End("the managed configuration cannot be read")
		return false
	}
	if managedFP(m) == managedFP(s.managed) {
		return true
	}
	s.managed = m
	// A new company policy: what it refused before is checked again.
	s.managedRefused, s.managedLines = "", nil
	_ = s.record(context.Background(), audit.Base{Event: audit.EventPolicy, Decision: DecisionManagedChanged})
	if m == nil {
		s.println(Paint.Step("the company's managed configuration was removed"))
	} else {
		s.println(Paint.Step("the company's managed configuration changed: " + sanitize.Terminal(m.Describe(), false)))
	}
	vs, err := managedViolations(s.cfg.Product, s.cfg.Backend, s.approved, m)
	if err == nil && len(vs) == 0 {
		return true
	}
	if cur, lerr := s.cfg.Backend.LoadPolicy(); lerr == nil {
		if cvs, cerr := managedViolations(s.cfg.Product, s.cfg.Backend, cur, m); cerr == nil && len(cvs) == 0 && !Loosens(cur.Diff(s.approved)) {
			changes := cur.Diff(s.approved)
			wasEnded := s.ended
			aerr := s.adopt(cur, "tightened")
			if s.ended && !wasEnded {
				return false
			}
			if aerr == nil {
				s.println("policy tightened to the company's managed configuration:")
				for _, line := range formatChangesOf(s.cfg.Backend, changes) {
					s.println(line)
				}
				return false
			}
		}
	}
	for _, line := range violationLines(vs, err) {
		s.println(red + sanitize.Terminal(line, false) + reset)
	}
	s.println(red + "the policy in force is beyond the company's managed configuration; the session ends: bring the config files within it and start again" + reset)
	s.End("the policy in force is beyond the managed configuration")
	return false
}

// refuseManagedChange refuses a policy read from the files that goes
// beyond the managed bounds: audited refused-managed once per policy,
// never pending, shown by :review as not approvable.
func (s *Server) refuseManagedChange(fp string, vs []managed.Violation, err error) {
	s.pending = nil
	if fp == s.managedRefused {
		return
	}
	s.managedRefused, s.managedLines = fp, violationLines(vs, err)
	_ = s.record(context.Background(), audit.Base{Event: audit.EventPolicy, Decision: DecisionRefusedManaged, Error: strings.Join(s.managedLines, "; ")})
	s.println(red + "policy change refused by the company's managed configuration (not approvable):" + reset)
	for _, line := range s.managedLines {
		s.println(red + "  " + sanitize.Terminal(line, false) + reset)
	}
	s.refreshStatus()
}

// Managed is the company's managed file in force (nil: none).
func (s *Server) Managed() *managed.File { return s.managed }
