package managed

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/DavidGodefroid/lockkit/config"
)

// Bounds are a tool's [<tool>.bounds] applied to one policy: what Check
// compares the policy with.
type Bounds struct {
	// Tool is the section's name ("locksql"), Profile the profile checked.
	Tool, Profile string
	// Ceiling is the checked policy with every bounded field set to its
	// bound: the loosest policy the managed file allows for this profile.
	// The tool builds it, and its own Diff then decides, as for an
	// approval, whether the policy loosens it. A list bound on a
	// single-valued field (credentials = ["vault", "ask"]) sets the field
	// to the policy's own value when it is in the list, and to the first
	// allowed value otherwise; an enforced value is a bound with one
	// allowed value. Nil: the file bounds nothing of this policy.
	Ceiling config.Policy
	// Keys maps a Diff field to its bound's key when they differ; a field
	// absent keeps its name (bounds are named after the profile keys).
	Keys map[string]string
}

// Violation is one field of a policy beyond its managed bound.
type Violation struct {
	// Key is the managed key that refuses it ("locksql.bounds.tier").
	Key string
	// Profile, Field and Value are the policy's; Bound is the ceiling's
	// value of the field ("" for a set element beyond an allowed set).
	Profile, Field, Value, Bound string
}

// String cites the managed key, as the consoles show it: "blocked by
// company policy: locksql.bounds.tier = write (profile dev: tier = ddl)".
// Values come from config files: a console escapes the line.
func (v Violation) String() string {
	switch {
	case v.Bound == "":
		return fmt.Sprintf("blocked by company policy: %s does not allow %s (profile %s: %s + %s)", v.Key, v.Value, v.Profile, v.Field, v.Value)
	case v.Value == "":
		return fmt.Sprintf("blocked by company policy: %s requires %s (profile %s: %s - %s)", v.Key, v.Bound, v.Profile, v.Field, v.Bound)
	}
	return fmt.Sprintf("blocked by company policy: %s = %s (profile %s: %s = %s)", v.Key, v.Bound, v.Profile, v.Field, v.Value)
}

// Check lists the fields of p that loosen b's ceiling: p.Diff(ceiling),
// the tool's own diff, marks each such field Loosens. A field tighter than
// its bound, or equal to it, is no violation. Nil when b bounds nothing.
func Check(p config.Policy, b Bounds) []Violation {
	if b.Ceiling == nil {
		return nil
	}
	var out []Violation
	for _, c := range p.Diff(b.Ceiling) {
		if !c.Loosens {
			continue
		}
		key := c.Field
		if k, ok := b.Keys[c.Field]; ok {
			key = k
		}
		out = append(out, Violation{Key: b.Tool + "." + KindBounds + "." + key, Profile: b.Profile, Field: c.Field, Value: c.New, Bound: c.Old})
	}
	return out
}

// ClampDuration is a duration within a managed maximum, the way ticket
// lifetimes are clamped (ticket.ClampTTL): a configured value of 0 or less
// (none, unlimited) or above max takes max; max of 0 or less bounds
// nothing.
func ClampDuration(configured, max time.Duration) time.Duration {
	if max <= 0 {
		return configured
	}
	if configured <= 0 || configured > max {
		return max
	}
	return configured
}

// MergeProfiles merges a tool's profiles by precedence: a project profile
// replaces a user profile of the same name as a whole, and a managed
// profile wins as a whole: a project or user profile of a managed name is
// refused, never merged nor ignored, so that the user knows the profile
// they wrote does not apply.
func MergeProfiles[T any](managed, project, user map[string]T) (map[string]T, error) {
	for _, name := range slices.Sorted(maps.Keys(managed)) {
		for _, f := range []struct {
			where string
			m     map[string]T
		}{{"project", project}, {"user", user}} {
			if _, ok := f.m[name]; ok {
				return nil, fmt.Errorf("managed: profile %q is provided by the company's managed configuration and cannot be redefined in the %s config: rename yours", name, f.where)
			}
		}
	}
	out := make(map[string]T, len(managed)+len(project)+len(user))
	maps.Copy(out, user)
	maps.Copy(out, project)
	maps.Copy(out, managed)
	return out, nil
}
