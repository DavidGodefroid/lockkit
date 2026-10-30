package ticket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// Renewal says that a ticket asks again for an expired one (decision H1):
// the same request, re-checked by the lock, with what changed in its
// plan-hash inputs since the expired ticket was made (and approved, when
// it was). A facade shows the changes and the human approves in one step;
// production still asks for the typed name.
type Renewal struct {
	// Of is the expired ticket.
	Of string `json:"of"`
	// Reason is why Of ended: RenewExpired or RenewApprovalExpired.
	Reason string `json:"reason"`
	// ApprovedAt is when Of was approved, for RenewApprovalExpired.
	ApprovedAt *time.Time `json:"approved_at"`
	// Checked: the lock compared the plan-hash inputs. False, Changes is
	// empty because the lock could not compare them (the run still checks
	// the plan hash, and refuses a stale plan).
	Checked bool `json:"checked"`
	// Changes are the inputs whose digest moved, by name.
	Changes []Change `json:"changes"`
}

// Renewal reasons.
const (
	// RenewExpired: the ticket expired before a decision.
	RenewExpired = "expired"
	// RenewApprovalExpired: the approval aged past its TTL before the run.
	RenewApprovalExpired = "approval-expired"
)

// Change is one plan-hash input that moved: its name and how. Names
// only: a digest of a short value (a name, an id) would let a hub confirm
// a guess, so neither values nor digests leave the lock.
type Change struct {
	Input string `json:"input"`
	// Change is ChangeChanged, ChangeNew or ChangeGone.
	Change string `json:"change"`
}

// Kinds of Change.
const (
	ChangeChanged = "changed"
	ChangeNew     = "new"
	ChangeGone    = "gone"
)

// MaxChanges bounds Renewal.Changes.
const MaxChanges = 64

// Unchanged reports whether a facade may present r as nothing changed:
// the lock checked, and no input moved.
func (r *Renewal) Unchanged() bool { return r != nil && r.Checked && len(r.Changes) == 0 }

func (r *Renewal) validate() error {
	switch {
	case !ValidID(r.Of):
		return invalid("renews.of %q is not a ULID", r.Of)
	case r.Reason != RenewExpired && r.Reason != RenewApprovalExpired:
		return invalid("renews.reason %q", r.Reason)
	case r.ApprovedAt != nil && (r.ApprovedAt.IsZero() || !normalized(*r.ApprovedAt)):
		return invalid("renews.approved_at: not a UTC millisecond time")
	case len(r.Changes) > MaxChanges:
		return invalid("renews.changes: more than %d", MaxChanges)
	case !r.Checked && len(r.Changes) > 0:
		return invalid("renews.changes without checked")
	}
	switch {
	case r.Reason == RenewApprovalExpired && r.ApprovedAt == nil:
		return invalid("renews: approval-expired without approved_at")
	case r.Reason == RenewExpired && r.ApprovedAt != nil:
		return invalid("renews: expired with approved_at")
	}
	for i, c := range r.Changes {
		if err := checkSet("renews.changes.input", c.Input); err != nil {
			return err
		}
		if i > 0 && r.Changes[i-1].Input >= c.Input {
			return invalid("renews.changes: not sorted by input, or an input twice")
		}
		if c.Change != ChangeChanged && c.Change != ChangeNew && c.Change != ChangeGone {
			return invalid("renews.changes.%s: change %q", c.Input, c.Change)
		}
	}
	return nil
}

// InputDigests names the inputs of a plan hash: for each member of the
// JSON object v encodes to, the HashOf its value. What a product hashes
// into its plan hash (a struct, a map) gives its inputs by field name.
// The digests stay in the lock (plans.Binding.Inputs): DiffInputs sends
// only the names of those that moved.
func InputDigests(v any) (map[string]string, error) {
	b, err := Canonical(v)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, fmt.Errorf("ticket: plan inputs are not a JSON object")
	}
	out := make(map[string]string, len(m))
	for k, raw := range m {
		h, err := HashOf(raw)
		if err != nil {
			return nil, err
		}
		out[k] = h
	}
	return out, nil
}

// DiffInputs lists the inputs whose digest differs between before and
// after, sorted by name; the first MaxChanges only (a plan has a handful
// of inputs).
func DiffInputs(before, after map[string]string) []Change {
	var names []string
	for k := range before {
		names = append(names, k)
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	var out []Change
	for _, k := range names {
		b, inB := before[k]
		a, inA := after[k]
		switch {
		case !inB:
			out = append(out, Change{Input: k, Change: ChangeNew})
		case !inA:
			out = append(out, Change{Input: k, Change: ChangeGone})
		case a != b:
			out = append(out, Change{Input: k, Change: ChangeChanged})
		}
	}
	if len(out) > MaxChanges {
		out = out[:MaxChanges]
	}
	return out
}
