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

// Change is one plan-hash input that moved: its name and its digest
// before and after ("" when the input is new or gone). Digests only, never
// values: a change shows what moved, not what it holds.
type Change struct {
	Input  string `json:"input"`
	Before string `json:"before"`
	After  string `json:"after"`
}

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
	for i, c := range r.Changes {
		if err := checkSet("renews.changes.input", c.Input); err != nil {
			return err
		}
		if i > 0 && r.Changes[i-1].Input >= c.Input {
			return invalid("renews.changes: not sorted by input, or an input twice")
		}
		for _, d := range []string{c.Before, c.After} {
			if d != "" && !validHash(d) {
				return invalid("renews.changes.%s: digest %q", c.Input, d)
			}
		}
		if c.Before == c.After {
			return invalid("renews.changes.%s: did not change", c.Input)
		}
	}
	return nil
}

// InputDigests names the inputs of a plan hash: for each member of the
// JSON object v encodes to, the HashOf its value. What a product hashes
// into its plan hash (a struct, a map) gives its inputs by field name.
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
		if before[k] != after[k] {
			out = append(out, Change{Input: k, Before: before[k], After: after[k]})
		}
	}
	if len(out) > MaxChanges {
		out = append(out[:MaxChanges-1], Change{Input: "￿ more", Before: "", After: hashPrefix + "0000000000000000000000000000000000000000000000000000000000000000"})
	}
	return out
}
