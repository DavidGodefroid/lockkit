package ticket

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Risk is the closed set of risk classes. Each product maps its operations
// onto one of them; the hub routes and expires tickets by risk alone, so a
// product cannot invent a class a facade does not know.
type Risk string

// The risk classes. RiskGrant asks for a grant: one approval for a
// bounded read scope (database, tables, duration, read budget) that the
// lock then runs reads inside without a ticket each. The scope is the
// plan: PlanHash is the hash of its canonical JSON (HashOf), so a decision
// binds exactly that scope, and the lock enforces it. A grant ticket is
// always NeverAuto.
const (
	RiskRead         Risk = "read"
	RiskReadPII      Risk = "read-pii"
	RiskGrant        Risk = "grant"
	RiskWrite        Risk = "write"
	RiskProdWrite    Risk = "prod-write"
	RiskPolicyLoosen Risk = "policy-loosen"
	RiskUnlock       Risk = "unlock"
)

// Risks lists every risk class, from the least to the most sensitive.
var Risks = []Risk{RiskRead, RiskReadPII, RiskGrant, RiskWrite, RiskProdWrite, RiskPolicyLoosen, RiskUnlock}

// ParseRisk returns the risk class named s; any other name is an error.
func ParseRisk(s string) (Risk, error) {
	for _, r := range Risks {
		if string(r) == s {
			return r, nil
		}
	}
	// The name given is not quoted: it may be a token pasted in the wrong
	// flag or key.
	return "", fmt.Errorf("ticket: unknown risk class: want one of %s", RiskNames())
}

// RiskNames lists Risks, comma-separated, for messages.
func RiskNames() string {
	names := make([]string, len(Risks))
	for i, r := range Risks {
		names[i] = string(r)
	}
	return strings.Join(names, ", ")
}

// Valid reports whether r is one of Risks.
func (r Risk) Valid() bool {
	_, err := ParseRisk(string(r))
	return err == nil
}

// UnmarshalJSON refuses a risk class outside Risks.
func (r *Risk) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseRisk(s)
	if err != nil {
		return err
	}
	*r = v
	return nil
}

// TTL is how long a ticket of class r waits for a decision, and how long
// an approval stays usable once given. Reads last 1 h, so that a read left
// pending (a ticket the facade cannot decide) ends by itself; writes and
// policy loosening 24 h; grants, production writes and unlock (a secret
// typed for the lock) 4 h. A grant's own lifetime is part of its scope,
// not of the ticket.
func (r Risk) TTL() time.Duration {
	switch r {
	case RiskRead, RiskReadPII:
		return time.Hour
	case RiskWrite, RiskPolicyLoosen:
		return 24 * time.Hour
	default: // grant, prod-write, unlock, and the shortest for anything else
		return 4 * time.Hour
	}
}

// ClampTTL is the TTL of class r for an instance configured with
// configured: an instance may only shorten it. configured <= 0 keeps
// r.TTL(). (A TTL of 0, no expiry, is no risk class's any more; ClampTTL
// still treats it as the longest.)
func ClampTTL(r Risk, configured time.Duration) time.Duration {
	def := r.TTL()
	if configured <= 0 {
		return def
	}
	if def == 0 || configured < def {
		return configured
	}
	return def
}
